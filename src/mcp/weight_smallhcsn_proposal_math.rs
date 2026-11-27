// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fixed-size frozen-key quadratic solve. Its certificate is numerical, not interval arithmetic.
//! No model, gradients, file access, random search or external linear algebra is used.

use std::time::Instant;

pub(super) const WIDTH: usize = 10;
pub(super) const SENDERS: usize = 4;
pub(super) const RIDGE: f64 = 0.02;
pub(super) const PROTECT: f64 = 0.25;
pub(super) type Key = [f64; WIDTH];
pub(super) type Matrix = [[f64; SENDERS]; WIDTH];
type Hessian = [[f64; WIDTH]; WIDTH];

#[derive(Clone)]
pub(super) struct Observation {
	pub key: Key,
	pub residual: [f64; SENDERS],
}

pub(super) struct Solution {
	pub delta: Matrix,
	pub multiplier: f64,
	pub bisections: usize,
	pub linear_solves: usize,
	pub norm: f64,
	pub kkt_max_abs: f64,
	pub kkt_tolerance: f64,
	pub minimum_cholesky_pivot: f64,
	pub objective_before: f64,
	pub objective_after: f64,
}

fn check_time(deadline: Instant) -> Result<(), String> {
	if Instant::now() >= deadline {
		return Err("shared sender compiler deadline exceeded".into());
	}
	Ok(())
}

pub(super) fn norm(value: &Matrix) -> f64 {
	value
		.iter()
		.flatten()
		.fold(0.0_f64, |total, v| total.hypot(*v))
}

fn validate_key(key: &Key) -> bool {
	key.iter().all(|x| x.is_finite() && x.abs() <= 4096.0) && key[9] == 1.0
}

fn system(
	failed: &[Observation],
	protected: &[Key],
	deadline: Instant,
) -> Result<(Hessian, Matrix), String> {
	if failed.is_empty() || protected.is_empty() || failed.len() + protected.len() > 480 {
		return Err("one to 480 total rows and both failed/protected partitions required".into());
	}
	let mut h = [[0.0; WIDTH]; WIDTH];
	let mut rhs = [[0.0; SENDERS]; WIDTH];
	for row in failed {
		check_time(deadline)?;
		if !validate_key(&row.key)
			|| !row
				.residual
				.iter()
				.all(|x| x.is_finite() && x.abs() <= 64.0)
		{
			return Err(
				"finite bounded normalized keys and preactivation residuals required".into(),
			);
		}
		for i in 0..WIDTH {
			for j in 0..=i {
				h[i][j] += row.key[i] * row.key[j] / failed.len() as f64;
			}
			for s in 0..SENDERS {
				rhs[i][s] += row.key[i] * row.residual[s] / failed.len() as f64;
			}
		}
	}
	for key in protected {
		check_time(deadline)?;
		if !validate_key(key) {
			return Err("finite bounded protected keys required".into());
		}
		for i in 0..WIDTH {
			for j in 0..=i {
				h[i][j] += PROTECT * key[i] * key[j] / protected.len() as f64;
			}
		}
	}
	for i in 0..WIDTH {
		h[i][i] += RIDGE;
		for j in 0..i {
			h[j][i] = h[i][j];
		}
	}
	if !h
		.iter()
		.flatten()
		.chain(rhs.iter().flatten())
		.all(|x| x.is_finite())
	{
		return Err("nonfinite quadratic system".into());
	}
	Ok((h, rhs))
}

fn solve(
	h: &Hessian,
	rhs: &Matrix,
	multiplier: f64,
	deadline: Instant,
) -> Result<(Matrix, f64), String> {
	check_time(deadline)?;
	let mut l = [[0.0; WIDTH]; WIDTH];
	let mut minimum = f64::INFINITY;
	for i in 0..WIDTH {
		for j in 0..=i {
			let mut value = h[i][j] + if i == j { multiplier } else { 0.0 };
			for k in 0..j {
				value -= l[i][k] * l[j][k];
			}
			if i == j {
				// The real ridge Hessian is positive definite. Unreliable F64 elimination abstains.
				if !value.is_finite() || value < 0.01 {
					return Err("regularized Cholesky pivot failed its fixed numerical gate".into());
				}
				minimum = minimum.min(value);
				l[i][j] = value.sqrt();
			} else {
				l[i][j] = value / l[j][j];
			}
		}
	}
	let mut y = [[0.0; SENDERS]; WIDTH];
	for i in 0..WIDTH {
		for s in 0..SENDERS {
			let mut value = rhs[i][s];
			for k in 0..i {
				value -= l[i][k] * y[k][s];
			}
			y[i][s] = value / l[i][i];
		}
	}
	let mut result = [[0.0; SENDERS]; WIDTH];
	for i in (0..WIDTH).rev() {
		for s in 0..SENDERS {
			let mut value = y[i][s];
			for k in i + 1..WIDTH {
				value -= l[k][i] * result[k][s];
			}
			result[i][s] = value / l[i][i];
		}
	}
	if !result.iter().flatten().all(|x| x.is_finite()) {
		return Err("nonfinite shared solution".into());
	}
	Ok((result, minimum))
}

pub(super) fn objective(failed: &[Observation], protected: &[Key], delta: &Matrix) -> f64 {
	let mut value = RIDGE * norm(delta).powi(2);
	for row in failed {
		for s in 0..SENDERS {
			let predicted: f64 = (0..WIDTH).map(|i| row.key[i] * delta[i][s]).sum();
			value += (predicted - row.residual[s]).powi(2) / failed.len() as f64;
		}
	}
	for key in protected {
		for s in 0..SENDERS {
			let predicted: f64 = (0..WIDTH).map(|i| key[i] * delta[i][s]).sum();
			value += PROTECT * predicted.powi(2) / protected.len() as f64;
		}
	}
	value
}

pub(super) fn fit(
	failed: &[Observation],
	protected: &[Key],
	radius: f64,
	deadline: Instant,
) -> Result<Solution, String> {
	if !radius.is_finite() || radius <= 0.0 || radius > 1.0 {
		return Err("shared sender solve requires a radius in (0,1]".into());
	}
	let (h, rhs) = system(failed, protected, deadline)?;
	let (mut delta, mut minimum) = solve(&h, &rhs, 0.0, deadline)?;
	let mut multiplier = 0.0;
	let mut bisections = 0;
	let mut linear_solves = 1;
	if norm(&delta) > radius {
		let mut lower = 0.0;
		// For real positive-definite H, ||(H+eta I)^-1 G|| <= ||G||/eta.
		let mut upper = (norm(&rhs) / radius).max(1.0);
		if !upper.is_finite() {
			return Err("finite trust-region multiplier bracket unavailable".into());
		}
		let (upper_solution, upper_pivot) = solve(&h, &rhs, upper, deadline)?;
		linear_solves += 1;
		if norm(&upper_solution) > radius {
			return Err(
				"fixed upper multiplier is not numerically feasible; no bracket search".into(),
			);
		}
		delta = upper_solution;
		minimum = upper_pivot;
		for _ in 0..128 {
			check_time(deadline)?;
			let middle = lower + (upper - lower) * 0.5;
			if middle == lower || middle == upper {
				break;
			}
			let (candidate, pivot) = solve(&h, &rhs, middle, deadline)?;
			linear_solves += 1;
			bisections += 1;
			if norm(&candidate) > radius {
				lower = middle;
			} else {
				upper = middle;
				delta = candidate;
				minimum = pivot;
			}
		}
		multiplier = upper;
	}
	let mut max_residual = 0.0_f64;
	let mut max_scale = 1.0_f64;
	for i in 0..WIDTH {
		for s in 0..SENDERS {
			let mut residual = multiplier * delta[i][s] - rhs[i][s];
			let mut scale = (multiplier * delta[i][s]).abs() + rhs[i][s].abs();
			for j in 0..WIDTH {
				residual += h[i][j] * delta[j][s];
				scale += (h[i][j] * delta[j][s]).abs();
			}
			max_residual = max_residual.max(residual.abs());
			max_scale = max_scale.max(scale);
		}
	}
	let tolerance = 1e-10 * max_scale;
	let value_before = objective(failed, protected, &[[0.0; SENDERS]; WIDTH]);
	let value_after = objective(failed, protected, &delta);
	let result_norm = norm(&delta);
	if !max_residual.is_finite()
		|| max_residual > tolerance
		|| result_norm > radius
		|| !value_before.is_finite()
		|| !value_after.is_finite()
		|| value_after > value_before + 1e-10 * value_before.max(1.0)
		|| (multiplier > 0.0 && (radius - result_norm).abs() > 1e-10 * radius)
	{
		return Err(
			"fixed shared-solve stationarity, primal, complementarity or objective gate failed"
				.into(),
		);
	}
	check_time(deadline)?;
	Ok(Solution {
		delta,
		multiplier,
		bisections,
		linear_solves,
		norm: result_norm,
		kkt_max_abs: max_residual,
		kkt_tolerance: tolerance,
		minimum_cholesky_pivot: minimum,
		objective_before: value_before,
		objective_after: value_after,
	})
}

#[cfg(test)]
#[path = "weight_smallhcsn_proposal_math_tests.rs"]
mod tests;
