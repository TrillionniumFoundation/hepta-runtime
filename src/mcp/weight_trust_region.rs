// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! A bounded direct solve for a joint L2 ball around exactly represented F32 anchors.
//!
//! Each output may have a different positive-semidefinite weighted Gram matrix.
//! With lambda > 0, the real-arithmetic convex problem has a unique solution:
//! (H_j + mu I) delta_j = c_j, one common mu >= 0 across every output. The
//! squared radius is a joint Frobenius budget, not a separate radius per output.
//! We bracket and bisect that monotone secular equation without gradient steps.
//! Returned KKT checks are F64 numerical diagnostics, not outward-error proofs.
//! F32 lowering rounds each coefficient toward its anchor, then independently
//! checks the exact represented-number budget. No F32 optimality is asserted.

use super::{cholesky_solve, deadline, element, finite, normal_residual, objective};
use super::{Dimensions, RidgePlanParams, MAX_RELATIVE_RESIDUAL, MAX_WORK};
use crate::mcp::weight_norm;
use crate::mcp::weight_tensor::ExactElementEdit;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::time::Instant;

const MAX_SHIFT_SOLVES: u64 = 96;
const MAX_BRACKET_STEPS: usize = 8;
const MAX_BISECTION_STEPS: usize = 80;
const RADIUS_TOLERANCE: f64 = 1e-10;

fn fixed_work(n: u64, p: u64, o: u64) -> u64 {
	// Includes centered normal equations, three full objectives, final KKT
	// recomputation, lowering and the fixed-width exact F32 budget check.
	o * (n * (p * p + 12 * p + 32) + 48 * p * p + 1024 * p + 128)
}

fn shifted_work(p: u64, o: u64) -> u64 {
	// Conservative scalar-operation model for every shift, factorization,
	// triangular substitution, residual check and joint norm, including brackets.
	o * (p * p * p + 16 * p * p + 32 * p)
}

pub(super) fn maximum_work(n: u64, p: u64, o: u64, singleton: bool) -> u64 {
	fixed_work(n, p, o)
		+ if singleton {
			0
		} else {
			MAX_SHIFT_SOLVES * shifted_work(p, o)
		}
}

struct Work {
	used: u64,
	per_shift: u64,
	shifts: u64,
	maximum: u64,
}

impl Work {
	fn admit_shift(&mut self) -> Result<()> {
		let next = self.used.checked_add(self.per_shift);
		if self.shifts >= MAX_SHIFT_SOLVES
			|| next.is_none_or(|next| next > MAX_WORK || next > self.maximum)
		{
			bail!("trust-region solve exhausted its pre-admitted arithmetic budget");
		}
		self.used += self.per_shift;
		self.shifts += 1;
		Ok(())
	}
}

struct Equation {
	matrix: Vec<f64>,
	rhs: Vec<f64>,
	positive_rows: usize,
}

fn centered_equation(
	params: &RidgePlanParams,
	dims: Dimensions,
	head: usize,
	end: Instant,
) -> Result<Equation> {
	let p = dims.features;
	let mut matrix = vec![0.0; p * p];
	let mut rhs = vec![0.0; p];
	for j in 0..p {
		matrix[j * p + j] = params.lambda;
	}
	let mut positive_rows = 0;
	for i in 0..dims.rows {
		deadline(end)?;
		let weight = params.sample_weights[i][head];
		if weight == 0.0 {
			continue;
		}
		positive_rows += 1;
		let prediction = params.features[i]
			.iter()
			.zip(&params.base_weights[head])
			.fold(0.0_f64, |sum, (x, b)| x.mul_add(*b, sum));
		let error = finite(params.targets[i][head] - prediction, "centered target")?;
		let scale = weight.sqrt();
		let target = finite(scale * error, "weighted centered target")?;
		let row: Vec<f64> = params.features[i]
			.iter()
			.map(|x| finite(scale * x, "weighted feature"))
			.collect::<Result<_>>()?;
		for j in 0..p {
			rhs[j] = finite(row[j].mul_add(target, rhs[j]), "centered right-hand side")?;
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
	Ok(Equation {
		matrix,
		rhs,
		positive_rows,
	})
}

fn shifted_matrix(equation: &Equation, p: usize, multiplier: f64) -> Result<Vec<f64>> {
	let mut matrix = equation.matrix.clone();
	for j in 0..p {
		matrix[j * p + j] = finite(matrix[j * p + j] + multiplier, "trust-region shift")?;
	}
	Ok(matrix)
}

fn norm<'a>(values: impl IntoIterator<Item = &'a f64>) -> Result<f64> {
	finite(
		values.into_iter().fold(0.0_f64, |sum, x| sum.hypot(*x)),
		"joint norm",
	)
}

fn solve_shift(
	equations: &[Equation],
	p: usize,
	multiplier: f64,
	work: &mut Work,
	end: Instant,
) -> Result<Vec<Vec<f64>>> {
	deadline(end)?;
	work.admit_shift()?;
	equations
		.iter()
		.map(|equation| {
			let matrix = shifted_matrix(equation, p, multiplier)?;
			let delta = cholesky_solve(&matrix, &equation.rhs, p, end)?;
			if normal_residual(&matrix, &equation.rhs, &delta, p)? > MAX_RELATIVE_RESIDUAL {
				bail!("trust-region shifted-system residual exceeds 1e-10");
			}
			Ok(delta)
		})
		.collect()
}

struct Solution {
	deltas: Vec<Vec<f64>>,
	multiplier: Option<f64>,
	active: bool,
	bisection_steps: usize,
	bracket_steps: usize,
}

fn constrained_solution(
	equations: &[Equation],
	dims: Dimensions,
	radius: f64,
	lambda: f64,
	work: &mut Work,
	end: Instant,
) -> Result<Solution> {
	if radius == 0.0 {
		// A singleton feasible set has an exact answer without a finite KKT multiplier.
		return Ok(Solution {
			deltas: vec![vec![0.0; dims.features]; dims.outputs],
			multiplier: None,
			active: true,
			bisection_steps: 0,
			bracket_steps: 0,
		});
	}
	let unconstrained = solve_shift(equations, dims.features, 0.0, work, end)?;
	if norm(unconstrained.iter().flatten())? <= radius {
		return Ok(Solution {
			deltas: unconstrained,
			multiplier: Some(0.0),
			active: false,
			bisection_steps: 0,
			bracket_steps: 0,
		});
	}
	let rhs_norm = norm(equations.iter().flat_map(|equation| &equation.rhs))?;
	// For exact SPD equations, ||delta(mu)|| <= ||c|| / mu. Explicit solves
	// still verify the bracket, and every numerical retry consumes the same budget.
	let mut upper = finite(rhs_norm / radius, "trust-region multiplier bracket")?.max(lambda);
	let mut feasible = None;
	let mut bracket_steps = 0;
	for _ in 0..MAX_BRACKET_STEPS {
		bracket_steps += 1;
		let candidate = solve_shift(equations, dims.features, upper, work, end)?;
		if norm(candidate.iter().flatten())? <= radius {
			feasible = Some(candidate);
			break;
		}
		upper = finite(2.0 * upper, "trust-region bracket expansion")?;
	}
	let mut candidate =
		feasible.ok_or_else(|| anyhow::anyhow!("trust-region feasible bracket not established"))?;
	let mut lower = 0.0;
	let mut bisection_steps = 0;
	for _ in 0..MAX_BISECTION_STEPS {
		let candidate_norm = norm(candidate.iter().flatten())?;
		if ((radius - candidate_norm) / radius).abs() <= 1e-12 {
			break;
		}
		let middle = lower + (upper - lower) * 0.5;
		if middle == lower || middle == upper {
			break;
		}
		bisection_steps += 1;
		let next = solve_shift(equations, dims.features, middle, work, end)?;
		if norm(next.iter().flatten())? > radius {
			lower = middle;
		} else {
			upper = middle;
			candidate = next;
		}
	}
	if ((radius - norm(candidate.iter().flatten())?) / radius).abs() > RADIUS_TOLERANCE {
		bail!("trust-region boundary accuracy not established within the bounded solve");
	}
	Ok(Solution {
		deltas: candidate,
		multiplier: Some(upper),
		active: true,
		bisection_steps,
		bracket_steps,
	})
}

fn lower_toward_anchor(value: f64, anchor: f64) -> Result<f32> {
	if value == anchor {
		return Ok(anchor as f32);
	}
	let mut lowered = value as f32;
	if !lowered.is_finite() {
		bail!("trust-region candidate cannot be represented as finite F32");
	}
	if value > anchor && f64::from(lowered) > value {
		lowered = lowered.next_down();
	} else if value < anchor && f64::from(lowered) < value {
		lowered = lowered.next_up();
	}
	Ok(lowered)
}

pub(super) fn solve(
	params: &RidgePlanParams,
	dims: Dimensions,
	radius: f64,
	started: Instant,
	end: Instant,
	request_sha256: String,
	request_bytes: usize,
) -> Result<Value> {
	let mut work = Work {
		used: fixed_work(dims.rows as u64, dims.features as u64, dims.outputs as u64),
		per_shift: shifted_work(dims.features as u64, dims.outputs as u64),
		shifts: 0,
		maximum: dims.work,
	};
	let equations = (0..dims.outputs)
		.map(|head| centered_equation(params, dims, head, end))
		.collect::<Result<Vec<_>>>()?;
	let solution = constrained_solution(&equations, dims, radius, params.lambda, &mut work, end)?;
	let mut weights_f64 = Vec::new();
	let mut weights_f32 = Vec::new();
	let mut edits = Vec::new();
	let mut diagnostics = Vec::new();
	let mut actual_deltas = Vec::new();
	let mut gradients = Vec::new();
	let mut candidate_rounding = 0.0_f64;
	let mut maximum_residual = 0.0_f64;
	for (head, equation) in equations.iter().enumerate() {
		deadline(end)?;
		let weights = params.base_weights[head]
			.iter()
			.zip(&solution.deltas[head])
			.map(|(base, delta)| finite(base + delta, "trust-region candidate"))
			.collect::<Result<Vec<_>>>()?;
		let deltas: Vec<f64> = weights
			.iter()
			.zip(&params.base_weights[head])
			.map(|(value, base)| value - base)
			.collect();
		let residual = if let Some(multiplier) = solution.multiplier {
			let matrix = shifted_matrix(equation, dims.features, multiplier)?;
			let residual = normal_residual(&matrix, &equation.rhs, &deltas, dims.features)?;
			if residual > MAX_RELATIVE_RESIDUAL {
				bail!("represented F64 candidate fails trust-region stationarity accuracy");
			}
			maximum_residual = maximum_residual.max(residual);
			Some(residual)
		} else {
			None
		};
		for j in 0..dims.features {
			let mut gradient = -equation.rhs[j];
			for (k, delta) in deltas.iter().enumerate() {
				gradient = equation.matrix[j * dims.features + k].mul_add(*delta, gradient);
			}
			gradients.push(finite(gradient, "trust-region final gradient diagnostic")?);
		}
		let lowered = weights
			.iter()
			.zip(&params.base_weights[head])
			.map(|(value, base)| lower_toward_anchor(*value, *base))
			.collect::<Result<Vec<_>>>()?;
		let lowered64: Vec<f64> = lowered.iter().map(|value| f64::from(*value)).collect();
		for j in 0..dims.features {
			candidate_rounding = candidate_rounding.max((lowered64[j] - weights[j]).abs());
			let base = params.base_weights[head][j] as f32;
			if base.to_bits() != lowered[j].to_bits() {
				edits.push(ExactElementEdit {
					index: (head * dims.features + j) as u64,
					expected_hex: element(base),
					replacement_hex: element(lowered[j]),
				});
			}
		}
		let before = objective(params, &params.base_weights[head], head)?;
		let after = objective(params, &weights, head)?;
		let after_f32 = objective(params, &lowered64, head)?;
		if after > before && (after - before) / before.max(1.0) > 1e-10 {
			bail!("trust-region F64 solution increases the fitted objective beyond numerical tolerance");
		}
		diagnostics.push(
			json!({"output":head,"positive_weight_rows":equation.positive_rows,
			"objective_before_f64":before,"objective_before_f32":before,"objective_after_f64":after,
			"objective_after_f32":after_f32,"relative_shifted_stationarity_residual_f64":residual,
			"f32_objective_strictly_improved":after_f32 < before}),
		);
		weights_f64.push(weights);
		weights_f32.push(lowered);
		actual_deltas.extend(deltas);
	}
	let actual_norm = norm(&actual_deltas)?;
	if radius == 0.0 {
		if actual_norm != 0.0 {
			bail!("zero-radius candidate differs from its singleton anchor");
		}
	} else if actual_norm / radius > 1.0 + RADIUS_TOLERANCE
		|| (solution.active && (actual_norm / radius - 1.0).abs() > RADIUS_TOLERANCE)
	{
		bail!("represented F64 candidate fails the numerical joint-radius check");
	}
	let f32_budget = weight_norm::check_pairs(
		params
			.base_weights
			.iter()
			.flatten()
			.zip(weights_f32.iter().flatten())
			.map(|(before, after)| (*before as f32, *after)),
		radius,
	)?;
	if !f32_budget.within_budget {
		bail!("F32 lowering exceeds the exact joint update budget; no patch proposal returned");
	}
	let gradient_norm = norm(&gradients)?;
	let dot = actual_deltas
		.iter()
		.zip(&gradients)
		.fold(0.0_f64, |sum, (delta, gradient)| {
			delta.mul_add(*gradient, sum)
		});
	let gap = 2.0 * (dot + radius * gradient_norm);
	let gap = gap.is_finite().then_some(gap);
	deadline(end)?;
	Ok(json!({"schema":"hepta.weight.proximal-ridge-plan.v1",
		"method":"supervised_proximal_weighted_ridge_joint_l2_trust_region_f64",
		"objective":"sum_j sum_i sample_weights[i][j]*(features[i] dot weights[j]-targets[i][j])^2 + lambda*sum_j||weights[j]-base_weights[j]||^2; no row normalization",
		"constraint":"one joint L2/Frobenius ball across all outputs around the exact F32 anchor",
		"rows":dims.rows,"features":dims.features,"outputs":dims.outputs,"lambda":params.lambda,
		"max_update_l2_norm":radius,"weights_f64":weights_f64,"weights_f32":weights_f32,
		"diagnostics":diagnostics,"f32_element_edits":edits,"f32_edit_count":edits.len(),
		"f32_tensor_layout":"[outputs,features], row-major little endian",
		"base_f32_rounding_max_absolute":0.0,"candidate_f32_rounding_max_absolute":candidate_rounding,
		"f32_lowering":"toward_anchor_then_exact_dyadic_joint_budget_check",
		"f32_update_budget":f32_budget,"f32_optimality_certified":false,
		"trust_region":{"singleton":radius == 0.0,"constraint_active":solution.active,
			"shared_multiplier":solution.multiplier,"f64_update_l2_norm":actual_norm,
			"relative_radius_slack_f64":if radius > 0.0 {Some(1.0-actual_norm/radius)} else {None},
			"maximum_relative_stationarity_residual_f64":if radius > 0.0 {Some(maximum_residual)} else {None},
			"frank_wolfe_gap_f64_diagnostic":gap,"f64_global_optimality_certified":false,
			"numerical_kkt_checks_passed":radius > 0.0,"singleton_feasibility_verified":radius == 0.0,
			"shift_solve_batches":work.shifts,"bracket_steps":solution.bracket_steps,"bisection_steps":solution.bisection_steps},
		"request_sha256":request_sha256,"request_bytes":request_bytes,
		"operation_budget_units":dims.work,"operation_charged_units":work.used,
		"native_operation_wall_seconds":started.elapsed().as_secs_f64(),"training_targets_used":true,"gradient_steps":0,
		"source_weights_verified":false,"requires_pinned_source_and_guarded_evaluation":true,
		"production_eligible":false,"independent_holdout_verified":false,
		"scope":"bounded convex F64 supervised fitting with exact represented-F32 update feasibility; no F32 optimum, authenticated source, task-value improvement or activation claim"}))
}

#[cfg(test)]
#[path = "weight_trust_region_tests.rs"]
mod tests;
