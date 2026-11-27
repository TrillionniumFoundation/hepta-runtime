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

//! Pure, bounded F32 affine-coordinate proposals for the existing cohort owner.
//! Caller-supplied coordinate relations are not checkpoint-bug or value evidence.
//! This module never publishes, evaluates, trains, selects or activates a model.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path};

use super::weight_artifact::cohort;
use super::weight_norm::{self, F32UpdateBudget};
use super::weight_tensor::ExactElementEdit;

#[path = "weight_affine_source.rs"]
mod source;

const MAX_WIDTH: usize = 32;
const MAX_ELEMENTS: usize = 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TensorBinding {
	pub name: String,
	pub dtype: String,
	pub shape: Vec<u64>,
	/// SHA-256 of this tensor's exact payload, in addition to the whole source SHA.
	pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AffineTransform {
	/// Explicit relation u_old = matrix * u_new + offset; not inferred here.
	pub matrix: Vec<Vec<f64>>,
	pub offset: Vec<f64>,
	pub old_mean: Vec<f64>,
	pub new_mean: Vec<f64>,
	/// Positive diagonal scales in z = (u - mean) / scale.
	pub old_scale: Vec<f64>,
	pub new_scale: Vec<f64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AffineParams {
	pub request_id: String,
	/// Explicit future-owner path; the compiler does not open or authorize it.
	pub path: String,
	pub source_sha256: String,
	/// Names and hashes bind bytes, not the claimed semantic W/b role in a graph.
	pub weights: TensorBinding,
	pub bias: TensorBinding,
	pub transform: AffineTransform,
	pub weights_maximum_update_l2_norm: f64,
	pub bias_maximum_update_l2_norm: f64,
	pub maximum_update_l2_norm: f64,
	/// External commitments bind claims, not their independent truth or authority.
	pub data_manifest_sha256: String,
	pub objective_sha256: String,
	pub dependency_manifest_sha256: String,
}

#[derive(Default, Serialize)]
struct Rounding {
	coefficients_lowered: usize,
	coefficients_rounded: usize,
	nonzero_underflowed_to_zero: usize,
	maximum_absolute_cast_difference: f64,
}

impl Rounding {
	fn lower(&mut self, value: f64) -> Result<f32> {
		let represented = finite(value)? as f32;
		if !represented.is_finite() {
			bail!("affine coefficient overflows finite F32 representation");
		}
		self.coefficients_lowered += 1;
		self.coefficients_rounded +=
			usize::from(f64::from(represented).to_bits() != value.to_bits());
		self.nonzero_underflowed_to_zero += usize::from(value != 0. && represented == 0.);
		self.maximum_absolute_cast_difference = self
			.maximum_absolute_cast_difference
			.max((f64::from(represented) - value).abs());
		Ok(represented)
	}
}

/// Serialize-only evidence and an explicit handoff, never an authorization token.
#[derive(Serialize)]
pub struct AffineProposal {
	schema: &'static str,
	source_sha256: String,
	candidate_sha256: String,
	header_sha256: String,
	request_sha256: String,
	transform_sha256: String,
	compiler_source_sha256: String,
	weights: TensorBinding,
	bias: TensorBinding,
	explicit_identity: bool,
	rounding: Option<Rounding>,
	member_budgets: [F32UpdateBudget; 2],
	global_budget: F32UpdateBudget,
	cohort: Option<cohort::PatchParams>,
	external_relation_verified: bool,
	encoded_forward_equivalence_verified: bool,
	behavior_evaluated: bool,
	production_eligible: bool,
}

impl AffineProposal {
	pub fn is_keep(&self) -> bool {
		self.cohort.is_none()
	}

	/// The caller still needs existing owner and final-use admission; no call occurs here.
	pub fn cohort_proposal(&self) -> Option<&cohort::PatchParams> {
		self.cohort.as_ref()
	}
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha(bytes: &[u8]) -> String {
	hex(&Sha256::digest(bytes))
}

fn finite(value: f64) -> Result<f64> {
	if !value.is_finite() {
		bail!("affine arithmetic requires finite inputs and intermediate values");
	}
	Ok(value)
}

fn validate(params: &AffineParams) -> Result<()> {
	if [
		&params.request_id,
		&params.source_sha256,
		&params.weights.sha256,
		&params.bias.sha256,
		&params.data_manifest_sha256,
		&params.objective_sha256,
		&params.dependency_manifest_sha256,
	]
	.into_iter()
	.any(|value| !super::weight_config::valid_sha256(value))
		|| params.path.len() > 4096
		|| params.path.as_bytes().contains(&0)
		|| !Path::new(&params.path).is_absolute()
		|| Path::new(&params.path)
			.components()
			.any(|part| matches!(part, Component::ParentDir | Component::CurDir))
	{
		bail!("affine proposal requires explicit digests and an absolute owner path");
	}
	if params.weights.name == params.bias.name
		|| [&params.weights, &params.bias].into_iter().any(|binding| {
			binding.name.is_empty()
				|| binding.name.len() > 1024
				|| binding.name == "__metadata__"
				|| binding.dtype != "F32"
		}) || params.weights.shape.len() != 2
		|| params.bias.shape.len() != 1
	{
		bail!("affine proposal requires distinct, explicit F32 W and b tensors");
	}
	let outputs = params.weights.shape[0];
	let inputs = params.weights.shape[1];
	if !(1..=MAX_WIDTH as u64).contains(&inputs)
		|| !(1..=MAX_WIDTH as u64).contains(&outputs)
		|| params.bias.shape[0] != outputs
		|| outputs * (inputs + 1) > MAX_ELEMENTS as u64
	{
		bail!("affine proposal cannot resize tensors or exceed its dimension profile");
	}
	let n = usize::try_from(inputs)?;
	let t = &params.transform;
	if t.matrix.len() != n
		|| t.matrix.iter().any(|row| row.len() != n)
		|| [
			&t.offset,
			&t.old_mean,
			&t.new_mean,
			&t.old_scale,
			&t.new_scale,
		]
		.into_iter()
		.any(|values| values.len() != n)
	{
		bail!("affine coordinate arrays must retain the exact input width");
	}
	for value in t
		.matrix
		.iter()
		.flatten()
		.chain(&t.offset)
		.chain(&t.old_mean)
		.chain(&t.new_mean)
		.chain(&t.old_scale)
		.chain(&t.new_scale)
	{
		finite(*value)?;
	}
	if t.old_scale
		.iter()
		.chain(&t.new_scale)
		.any(|value| *value <= 0.)
	{
		bail!("affine normalization scales must be finite and positive");
	}
	for radius in [
		params.weights_maximum_update_l2_norm,
		params.bias_maximum_update_l2_norm,
		params.maximum_update_l2_norm,
	] {
		weight_norm::validate_radius(radius)?;
	}
	Ok(())
}

fn identity(t: &AffineTransform) -> bool {
	t.old_mean == t.new_mean
		&& t.old_scale == t.new_scale
		&& t.offset.iter().all(|value| *value == 0.)
		&& t.matrix.iter().enumerate().all(|(i, row)| {
			row.iter()
				.enumerate()
				.all(|(j, value)| *value == if i == j { 1. } else { 0. })
		})
}

fn coefficients(
	pair: &source::Pair<'_>,
	t: &AffineTransform,
) -> Result<(Vec<f32>, Vec<f32>, Rounding)> {
	let n = pair.inputs;
	let mut shift = Vec::with_capacity(n);
	for ((row, offset), old_mean) in t.matrix.iter().zip(&t.offset).zip(&t.old_mean) {
		let mut value = 0.;
		for (coefficient, new_mean) in row.iter().zip(&t.new_mean) {
			value = finite(value + finite(coefficient * new_mean)?)?;
		}
		shift.push(finite(finite(value + offset)? - old_mean)?);
	}
	let mut rounding = Rounding::default();
	let mut weights = Vec::with_capacity(pair.weights.values.len());
	let mut bias = Vec::with_capacity(pair.outputs);
	for (old_row, old_bias) in pair.weights.values.chunks_exact(n).zip(&pair.bias.values) {
		let scaled = old_row
			.iter()
			.zip(&t.old_scale)
			.map(|(weight, scale)| finite(f64::from(*weight) / scale))
			.collect::<Result<Vec<_>>>()?;
		for (j, new_scale) in t.new_scale.iter().enumerate() {
			let mut sum = 0.;
			for (weight, row) in scaled.iter().zip(&t.matrix) {
				sum = finite(sum + finite(weight * row[j])?)?;
			}
			weights.push(rounding.lower(finite(sum * new_scale)?)?);
		}
		let mut sum = f64::from(*old_bias);
		for (weight, shift) in scaled.iter().zip(&shift) {
			sum = finite(sum + finite(weight * shift)?)?;
		}
		bias.push(rounding.lower(sum)?);
	}
	Ok((weights, bias, rounding))
}

fn member(
	tensor: &source::Tensor<'_>,
	values: &[f32],
	radius: f64,
	replacements: &mut Vec<(usize, [u8; 4])>,
) -> Option<cohort::Member> {
	let mut edits = Vec::new();
	for (index, (before, value)) in tensor.bytes.chunks_exact(4).zip(values).enumerate() {
		let after = value.to_le_bytes();
		if before != after.as_slice() {
			edits.push(ExactElementEdit {
				index: index as u64,
				expected_hex: hex(before),
				replacement_hex: hex(&after),
			});
			replacements.push((tensor.file_offset + index * 4, after));
		}
	}
	(!edits.is_empty()).then(|| cohort::Member {
		tensor_name: tensor.binding.name.clone(),
		edits,
		maximum_update_l2_norm: radius,
	})
}

fn implementation_sha256() -> String {
	let mut hash = Sha256::new();
	hash.update(b"hepta.weight.affine-selected-source.v1\0");
	for (name, bytes) in [
		("compiler", include_bytes!("weight_affine.rs").as_slice()),
		(
			"source",
			include_bytes!("weight_affine_source.rs").as_slice(),
		),
		("inspector", include_bytes!("rea.rs").as_slice()),
		("unique_json", include_bytes!("rea_evidence.rs").as_slice()),
		("norm", include_bytes!("weight_norm.rs").as_slice()),
		("tensor", include_bytes!("weight_tensor.rs").as_slice()),
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
	hex(&hash.finalize())
}

/// Compile immutable bytes and external coordinate claims; perform no owner action.
/// Limits apply to this typed request, not to an as-yet-unprovided wire decoder.
pub fn compile(params: &AffineParams, checkpoint: &[u8]) -> Result<AffineProposal> {
	validate(params)?;
	let pair = source::authenticate(params, checkpoint)?;
	let explicit_identity = identity(&params.transform);
	let (weights, bias, rounding) = if explicit_identity {
		// Validation and exact budgets still run; do not divide/multiply away -0 bits.
		(pair.weights.values.clone(), pair.bias.values.clone(), None)
	} else {
		let (weights, bias, rounding) = coefficients(&pair, &params.transform)?;
		(weights, bias, Some(rounding))
	};
	let member_budgets = [
		weight_norm::check_pairs(
			pair.weights
				.values
				.iter()
				.copied()
				.zip(weights.iter().copied()),
			params.weights_maximum_update_l2_norm,
		)?,
		weight_norm::check_pairs(
			pair.bias.values.iter().copied().zip(bias.iter().copied()),
			params.bias_maximum_update_l2_norm,
		)?,
	];
	let global_budget = weight_norm::check_pairs(
		pair.weights
			.values
			.iter()
			.chain(&pair.bias.values)
			.copied()
			.zip(weights.iter().chain(&bias).copied()),
		params.maximum_update_l2_norm,
	)?;
	if member_budgets.iter().any(|budget| !budget.within_budget) || !global_budget.within_budget {
		bail!("affine represented coefficients exceed a declared exact L2 budget");
	}
	let mut replacements = Vec::new();
	let members: Vec<_> = [
		member(
			&pair.weights,
			&weights,
			params.weights_maximum_update_l2_norm,
			&mut replacements,
		),
		member(
			&pair.bias,
			&bias,
			params.bias_maximum_update_l2_norm,
			&mut replacements,
		),
	]
	.into_iter()
	.flatten()
	.collect();
	let candidate_sha256 = if members.is_empty() {
		params.source_sha256.clone()
	} else {
		source::candidate_sha256(checkpoint, &mut replacements)?
	};
	let request_sha256 = sha(&serde_json::to_vec(params)?);
	let transform_sha256 = sha(&serde_json::to_vec(&params.transform)?);
	let compiler_source_sha256 = implementation_sha256();
	let dependency = sha(&serde_json::to_vec(&serde_json::json!({
		"caller_dependency_manifest_sha256": params.dependency_manifest_sha256,
		"request_sha256": request_sha256, "transform_sha256": transform_sha256,
		"compiler_source_sha256": compiler_source_sha256
	}))?);
	let cohort = (!members.is_empty()).then(|| cohort::PatchParams {
		request_id: params.request_id.clone(),
		path: params.path.clone(),
		expected_sha256: params.source_sha256.clone(),
		identity: cohort::Identity {
			code_sha256: compiler_source_sha256.clone(),
			tensor_map_sha256: pair.tensor_map_sha256,
			data_manifest_sha256: params.data_manifest_sha256.clone(),
			objective_sha256: params.objective_sha256.clone(),
			dependency_manifest_sha256: dependency,
		},
		members,
		maximum_update_l2_norm: params.maximum_update_l2_norm,
		training: cohort::TrainingContract::InferenceOnly,
	});
	Ok(AffineProposal {
		schema: "hepta.weight.affine-f32-proposal.v1",
		source_sha256: params.source_sha256.clone(),
		candidate_sha256,
		header_sha256: pair.header_sha256,
		request_sha256,
		transform_sha256,
		compiler_source_sha256,
		weights: params.weights.clone(),
		bias: params.bias.clone(),
		explicit_identity,
		rounding,
		member_budgets,
		global_budget,
		cohort,
		external_relation_verified: false,
		encoded_forward_equivalence_verified: false,
		behavior_evaluated: false,
		production_eligible: false,
	})
}

#[cfg(test)]
#[path = "weight_affine_tests.rs"]
mod weight_affine_tests;
