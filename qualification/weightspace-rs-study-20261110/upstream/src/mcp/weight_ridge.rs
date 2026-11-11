// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded supervised proximal weighted-ridge planning for a small linear head.
//! Produces an unbound candidate, not an accepted edit or a model-quality claim.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

use super::weight_tensor::ExactElementEdit;

const MAX_FEATURES: usize = 64;
const MAX_ROWS: usize = 2048;
const MAX_OUTPUTS: usize = 8;
const MAX_WORK: u64 = 80_000_000;
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RELATIVE_RESIDUAL: f64 = 1e-10;
static PLANNERS: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RidgePlanParams {
	/// Finite F64 [rows,features], at most [2048,64]. An intercept must be explicit.
	pub features: Vec<Vec<f64>>,
	/// Finite F64 [rows,outputs]; these supervised targets are used for fitting.
	pub targets: Vec<Vec<f64>>,
	/// Nonnegative finite [rows,outputs] weights; each output has its own weights.
	pub sample_weights: Vec<Vec<f64>>,
	/// Finite F64 [outputs,features] proximal anchor, also convertible to finite F32.
	pub base_weights: Vec<Vec<f64>>,
	/// Positive finite coefficient, without implicit sample-count normalization.
	pub lambda: f64,
	/// Optional joint L2/Frobenius update radius across every output. Finite and
	/// nonnegative; zero returns the unchanged anchor. Requires exact F32 anchors.
	/// F64 KKT diagnostics and exact F32 feasibility do not certify F32 optimality.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_update_l2_norm: Option<f64>,
}

#[derive(Clone, Copy)]
struct Dimensions {
	rows: usize,
	features: usize,
	outputs: usize,
	work: u64,
}

fn validate(params: &RidgePlanParams) -> Result<Dimensions> {
	let rows = params.features.len();
	let outputs = params.base_weights.len();
	let features = params.features.first().map_or(0, Vec::len);
	if !(1..=MAX_ROWS).contains(&rows)
		|| !(1..=MAX_FEATURES).contains(&features)
		|| !(1..=MAX_OUTPUTS).contains(&outputs)
		|| !params.lambda.is_finite()
		|| params.lambda <= 0.0
	{
		bail!("ridge needs 1..2048 rows, 1..64 features, 1..8 outputs and finite lambda > 0");
	}
	if params
		.features
		.iter()
		.any(|row| row.len() != features || row.iter().any(|x| !x.is_finite()))
		|| params.base_weights.iter().any(|row| {
			row.len() != features
				|| row
					.iter()
					.any(|x| !x.is_finite() || !(*x as f32).is_finite())
		}) || params.targets.len() != rows
		|| params.sample_weights.len() != rows
		|| params
			.targets
			.iter()
			.any(|row| row.len() != outputs || row.iter().any(|x| !x.is_finite()))
		|| params
			.sample_weights
			.iter()
			.any(|row| row.len() != outputs || row.iter().any(|x| !x.is_finite() || *x < 0.0))
	{
		bail!("ridge arrays must have exact matching shapes and finite values; sample weights must be nonnegative and anchors convertible to finite F32");
	}
	let (n, p, o) = (rows as u64, features as u64, outputs as u64);
	// Conservative work units cover normal equations, solves, residuals and three objectives.
	let work = if let Some(radius) = params.max_update_l2_norm {
		super::weight_norm::validate_radius(radius)?;
		if params
			.base_weights
			.iter()
			.flatten()
			.any(|x| f64::from(*x as f32) != *x)
		{
			bail!("an L2-budgeted plan requires anchors exactly representable as finite F32");
		}
		trust_region::maximum_work(n, p, o, radius == 0.0)
	} else {
		o * (n * (p * p + 6 * p + 16) + p * p * p + 10 * p * p)
	};
	if work > MAX_WORK {
		bail!("ridge exceeds its scalar arithmetic work budget");
	}
	Ok(Dimensions {
		rows,
		features,
		outputs,
		work,
	})
}

fn finite(value: f64, operation: &str) -> Result<f64> {
	if !value.is_finite() {
		bail!("ridge numerical overflow in {operation}");
	}
	Ok(value)
}

fn deadline(deadline: Instant) -> Result<()> {
	if Instant::now() >= deadline {
		bail!("ridge planning exceeded its 30-second compute deadline");
	}
	Ok(())
}

fn normal_equations(
	params: &RidgePlanParams,
	dims: Dimensions,
	head: usize,
	end: Instant,
) -> Result<(Vec<f64>, Vec<f64>)> {
	let p = dims.features;
	let mut matrix = vec![0.0; p * p];
	let mut rhs = vec![0.0; p];
	for j in 0..p {
		matrix[j * p + j] = params.lambda;
		rhs[j] = finite(
			params.lambda * params.base_weights[head][j],
			"proximal right-hand side",
		)?;
	}
	for i in 0..dims.rows {
		deadline(end)?;
		let weight = params.sample_weights[i][head];
		if weight == 0.0 {
			continue;
		}
		let scale = weight.sqrt();
		let target = finite(scale * params.targets[i][head], "weighted target")?;
		let row: Vec<f64> = params.features[i]
			.iter()
			.map(|x| finite(scale * x, "weighted feature"))
			.collect::<Result<_>>()?;
		for j in 0..p {
			rhs[j] = finite(row[j].mul_add(target, rhs[j]), "normal right-hand side")?;
			for k in 0..=j {
				let index = j * p + k;
				matrix[index] = finite(row[j].mul_add(row[k], matrix[index]), "normal matrix")?;
			}
		}
	}
	for j in 0..p {
		for k in 0..j {
			matrix[k * p + j] = matrix[j * p + k];
		}
	}
	Ok((matrix, rhs))
}

fn cholesky_solve(matrix: &[f64], rhs: &[f64], p: usize, end: Instant) -> Result<Vec<f64>> {
	let mut factor = vec![0.0_f64; p * p];
	for j in 0..p {
		deadline(end)?;
		for k in 0..=j {
			let mut value = matrix[j * p + k];
			for i in 0..k {
				value = (-factor[j * p + i]).mul_add(factor[k * p + i], value);
			}
			finite(value, "Cholesky factorization")?;
			factor[j * p + k] = if j == k {
				if value <= 0.0 {
					bail!("ridge matrix lost positive definiteness at F64 precision; no jitter or penalty change was applied");
				}
				value.sqrt()
			} else {
				finite(value / factor[k * p + k], "Cholesky division")?
			};
		}
	}
	let mut solved = vec![0.0; p];
	for j in 0..p {
		let mut value = rhs[j];
		for k in 0..j {
			value = (-factor[j * p + k]).mul_add(solved[k], value);
		}
		solved[j] = finite(value / factor[j * p + j], "forward substitution")?;
	}
	for j in (0..p).rev() {
		let mut value = solved[j];
		for k in j + 1..p {
			value = (-factor[k * p + j]).mul_add(solved[k], value);
		}
		solved[j] = finite(value / factor[j * p + j], "back substitution")?;
	}
	Ok(solved)
}

fn normal_residual(matrix: &[f64], rhs: &[f64], weights: &[f64], p: usize) -> Result<f64> {
	let mut residual = 0.0_f64;
	let mut matrix_norm = 0.0_f64;
	let mut rhs_norm = 0.0_f64;
	let mut weight_norm = 0.0_f64;
	for j in 0..p {
		let mut value = -rhs[j];
		let mut row_norm = 0.0;
		for k in 0..p {
			value = matrix[j * p + k].mul_add(weights[k], value);
			row_norm += matrix[j * p + k].abs();
		}
		residual = residual.max(finite(value, "normal-equation residual")?.abs());
		matrix_norm = matrix_norm.max(finite(row_norm, "normal-matrix norm")?);
		rhs_norm = rhs_norm.max(rhs[j].abs());
		weight_norm = weight_norm.max(weights[j].abs());
	}
	let scale = finite(
		matrix_norm.mul_add(weight_norm, rhs_norm),
		"normal-residual scale",
	)?;
	if scale == 0.0 {
		if residual != 0.0 {
			bail!("ridge residual has a zero normalization scale");
		}
		return Ok(0.0);
	}
	finite(residual / scale, "relative normal-equation residual")
}

fn objective(params: &RidgePlanParams, weights: &[f64], head: usize) -> Result<f64> {
	let mut loss = 0.0;
	for (i, row) in params.features.iter().enumerate() {
		if params.sample_weights[i][head] == 0.0 {
			continue;
		}
		let prediction = row
			.iter()
			.zip(weights)
			.fold(0.0_f64, |sum, (x, w)| x.mul_add(*w, sum));
		let error = finite(prediction - params.targets[i][head], "objective prediction")?;
		let scaled = finite(
			params.sample_weights[i][head].sqrt() * error,
			"objective weighted error",
		)?;
		loss = finite(scaled.mul_add(scaled, loss), "weighted squared loss")?;
	}
	for (value, base) in weights.iter().zip(&params.base_weights[head]) {
		let difference = finite(value - base, "proximal difference")?;
		let scaled = finite(
			params.lambda.sqrt() * difference,
			"proximal difference scale",
		)?;
		loss = finite(scaled.mul_add(scaled, loss), "proximal objective")?;
	}
	Ok(loss)
}

fn element(value: f32) -> String {
	value
		.to_le_bytes()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

struct RequestCommitment {
	hash: Sha256,
	bytes: usize,
}

impl Write for RequestCommitment {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		let total = self
			.bytes
			.checked_add(bytes.len())
			.filter(|n| *n <= MAX_REQUEST_BYTES)
			.ok_or_else(|| std::io::Error::other("ridge request exceeds 4 MiB"))?;
		self.hash.update(bytes);
		self.bytes = total;
		Ok(bytes.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

fn solve(params: &RidgePlanParams) -> Result<Value> {
	let started = Instant::now();
	let end = started + Duration::from_secs(30);
	let dims = validate(params)?;
	let mut commitment = RequestCommitment {
		hash: Sha256::new(),
		bytes: 0,
	};
	serde_json::to_writer(&mut commitment, params).context("ridge request commitment failed")?;
	let request_sha256: String = commitment
		.hash
		.finalize()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect();
	if let Some(radius) = params.max_update_l2_norm {
		return trust_region::solve(
			params,
			dims,
			radius,
			started,
			end,
			request_sha256,
			commitment.bytes,
		);
	}
	let mut weights_f64 = Vec::with_capacity(dims.outputs);
	let mut weights_f32 = Vec::with_capacity(dims.outputs);
	let mut edits = Vec::new();
	let mut diagnostics = Vec::with_capacity(dims.outputs);
	let mut base_rounding = 0.0_f64;
	let mut candidate_rounding = 0.0_f64;
	for head in 0..dims.outputs {
		deadline(end)?;
		let (matrix, rhs) = normal_equations(params, dims, head, end)?;
		let positive_rows = params
			.sample_weights
			.iter()
			.filter(|row| row[head] > 0.0)
			.count();
		let before = objective(params, &params.base_weights[head], head)?;
		// With no weighted observations, the unique mathematical solution is exactly the anchor.
		let weights = if positive_rows == 0 || before == 0.0 {
			params.base_weights[head].clone()
		} else {
			cholesky_solve(&matrix, &rhs, dims.features, end)?
		};
		let residual = normal_residual(&matrix, &rhs, &weights, dims.features)?;
		if residual > MAX_RELATIVE_RESIDUAL {
			bail!("ridge normal-equation residual exceeds 1e-10 at output {head}");
		}
		let rounded: Vec<f32> = weights.iter().map(|x| *x as f32).collect();
		if rounded.iter().any(|x| !x.is_finite()) {
			bail!("ridge candidate cannot be represented as finite F32");
		}
		let rounded64: Vec<f64> = rounded.iter().map(|x| f64::from(*x)).collect();
		let base32: Vec<f64> = params.base_weights[head]
			.iter()
			.map(|x| f64::from(*x as f32))
			.collect();
		for j in 0..dims.features {
			let original = params.base_weights[head][j] as f32;
			base_rounding =
				base_rounding.max((f64::from(original) - params.base_weights[head][j]).abs());
			candidate_rounding = candidate_rounding.max((rounded64[j] - weights[j]).abs());
			if original.to_bits() != rounded[j].to_bits() {
				edits.push(ExactElementEdit {
					index: (head * dims.features + j) as u64,
					expected_hex: element(original),
					replacement_hex: element(rounded[j]),
				});
			}
		}
		let before_f32 = objective(params, &base32, head)?;
		let after = objective(params, &weights, head)?;
		let after_f32 = objective(params, &rounded64, head)?;
		if after > before && (after - before) / before.max(1.0) > 1e-10 {
			bail!("ridge F64 solution increases the fitted objective beyond numerical tolerance");
		}
		diagnostics.push(json!({"output":head,"positive_weight_rows":positive_rows,
			"objective_before_f64":before,"objective_before_f32":before_f32,"objective_after_f64":after,"objective_after_f32":after_f32,
			"relative_normal_equation_residual_f64":residual,
			"relative_normal_equation_residual_f32":normal_residual(&matrix,&rhs,&rounded64,dims.features)?,
			"f32_objective_strictly_improved":after_f32 < before_f32}));
		weights_f64.push(weights);
		weights_f32.push(rounded);
	}
	deadline(end)?;
	Ok(json!({"schema":"hepta.weight.proximal-ridge-plan.v1",
		"method":"supervised_proximal_weighted_ridge_cholesky_f64",
		"objective":"sum_i sample_weights[i][j] * (features[i] dot weights[j] - targets[i][j])^2 + lambda * ||weights[j]-base_weights[j]||^2; no division by row count",
		"rows":dims.rows,"features":dims.features,"outputs":dims.outputs,"lambda":params.lambda,
		"weights_f64":weights_f64,"weights_f32":weights_f32,"diagnostics":diagnostics,
		"f32_element_edits":edits,"f32_edit_count":edits.len(),"f32_tensor_layout":"[outputs,features], row-major little endian",
		"base_f32_rounding_max_absolute":base_rounding,"candidate_f32_rounding_max_absolute":candidate_rounding,
		"request_sha256":request_sha256,"request_bytes":commitment.bytes,"operation_budget_units":dims.work,
		"native_operation_wall_seconds":started.elapsed().as_secs_f64(),"training_targets_used":true,"gradient_steps":0,
		"source_weights_verified":false,"requires_pinned_source_and_guarded_evaluation":true,
		"production_eligible":false,"independent_holdout_verified":false,
		"scope":"closed-form supervised fitting of one bounded F32-exportable linear head; no file access, artifact publication, Astra circuit discovery or end-to-end value guarantee"}))
}

pub async fn plan(params: RidgePlanParams) -> Result<String> {
	validate(&params)?;
	let permit = PLANNERS
		.get_or_init(|| Arc::new(Semaphore::new(2)))
		.clone()
		.try_acquire_owned()
		.map_err(|_| anyhow!("native ridge planning capacity exhausted; no work admitted"))?;
	let result = tokio::task::spawn_blocking(move || {
		// A dropped caller cannot release capacity while its original CPU work is still running.
		let _permit = permit;
		solve(&params)
	})
	.await
	.context("native ridge planning worker failed")??;
	Ok(serde_json::to_string(&result)?)
}

#[path = "weight_trust_region.rs"]
mod trust_region;

#[cfg(test)]
#[path = "weight_ridge_tests.rs"]
mod tests;
