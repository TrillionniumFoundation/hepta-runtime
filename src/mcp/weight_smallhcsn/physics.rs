// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Complete F64 boundary, reset, first-passage, marked-flow and reward operators.
use super::matrix::Matrix;
use anyhow::{ensure, Result};

pub(super) const DT: f64 = 0.48;
const SIGMA: f64 = 0.55;
const RHO: f64 = 0.3;
const H: f64 = 2.0 / 6.0;
const TOLERANCE: f64 = 2e-9;
pub(super) fn centers() -> [f64; 6] {
	std::array::from_fn(|i| (i as f64 * H + (i + 1) as f64 * H) / 2.0)
}
fn deposit(margin: f64) -> Result<[f64; 6]> {
	let centers = centers();
	ensure!(
		margin > centers[0] && margin < centers[5],
		"reset outside supported cell hull"
	);
	Ok(std::array::from_fn(|i| {
		(1.0 - (margin - centers[i]).abs() / H).clamp(0.0, 1.0)
	}))
}
pub(super) fn qvi(mu: f64, cost: f64, absolute: f64) -> Result<f64> {
	let root = (mu * mu + 2.0 * RHO * SIGMA * SIGMA).sqrt();
	let k = if mu >= 0.0 {
		(mu + root) / (SIGMA * SIGMA)
	} else {
		2.0 * RHO / (root - mu)
	};
	let slope = 0.8 / RHO;
	let intercept = 0.8 * mu / (RHO * RHO) - 0.25 / RHO;
	let amplitude = slope / k;
	let eta = (-3.0 * (RHO * 0.2 / 3.0).ln_1p()).exp();
	let residual = |b: f64| {
		slope * b + intercept + amplitude + cost
			- eta * (slope * absolute + intercept + amplitude * (-k * (absolute - b)).exp())
	};
	let (mut low, mut high) = (absolute - 8.0, absolute - 1e-4);
	ensure!(
		residual(low) < 0.0 && residual(high) > 0.0,
		"QVI bracket violation"
	);
	for _ in 0..56 {
		let mid = (low + high) / 2.0;
		if residual(mid) < 0.0 {
			low = mid;
		} else {
			high = mid;
		}
	}
	Ok((low + high) / 2.0)
}
pub(super) struct Operators {
	propagate: Matrix,
	first: [f64; 10],
	value: [f64; 10],
}
pub(super) fn operators(mu: f64, boundary: f64, cost: f64, absolute: f64) -> Result<Operators> {
	let diffusion = SIGMA * SIGMA / (2.0 * H * H);
	let mut left = [(-mu).max(0.0) / H + diffusion; 6];
	let mut right = [mu.max(0.0) / H + diffusion; 6];
	left[0] += diffusion;
	right[5] += diffusion;
	let mut g = Matrix::zero(10);
	for (i, (left_rate, right_rate)) in left.iter().zip(&right).enumerate() {
		g.a[i * 10 + i] = -left_rate - right_rate;
		if i > 0 {
			g.a[i * 10 + i - 1] = *left_rate;
		}
		if i < 5 {
			g.a[i * 10 + i + 1] = *right_rate;
		}
	}
	g.a[55] += right[5];
	g.a[6] = left[0];
	for i in 6..9 {
		g.a[i * 10 + i] = -15.0;
	}
	g.a[67] = 15.0;
	g.a[78] = 15.0;
	for (j, p) in deposit(absolute - boundary)?.iter().enumerate() {
		g.a[80 + j] = 15.0 * p;
	}
	ensure!(
		(0..10).all(|i| g.a[i * 10..i * 10 + 10].iter().sum::<f64>().abs() < 1e-12),
		"generator mass conservation"
	);
	let mut aug = Matrix::zero(12);
	let mut killed = Matrix::zero(11);
	for i in 0..10 {
		for j in 0..10 {
			aug.a[i * 12 + j] = g.a[i * 10 + j];
			killed.a[i * 11 + j] = g.a[i * 10 + j];
		}
	}
	aug.a[10] = left[0];
	for i in 0..6 {
		aug.a[i * 12 + 11] = 1.0;
	}
	killed.a[6] -= left[0];
	killed.a[10] = left[0];
	let propagate = aug.scale(DT).exp()?;
	let first_matrix = killed.scale(DT).exp()?;
	let first = std::array::from_fn(|i| first_matrix.a[i * 11 + 10]);
	let mut reward = Matrix::zero(10);
	for (i, x) in centers().iter().enumerate() {
		reward.a[i * 10] = 0.8 * (boundary + x) - 0.25;
	}
	reward.a[0] -= cost * left[0];
	let solved = Matrix::eye(10).scale(RHO).add(&g, -1.0).solve(&reward)?;
	let value = std::array::from_fn(|i| solved.a[i * 10]);
	Ok(Operators {
		propagate,
		first,
		value,
	})
}
#[derive(Clone)]
pub(super) struct Population {
	pub boundary: f64,
	p: [f64; 10],
	q: [f64; 10],
}
impl Population {
	pub fn new(boundary: f64, absolute: f64) -> Result<Self> {
		let mut p = [0.0; 10];
		p[..6].copy_from_slice(&deposit(absolute - boundary)?);
		Ok(Self {
			boundary,
			p,
			q: [0.0; 10],
		})
	}
	pub fn flow(
		&mut self,
		next_boundary: f64,
		mark: f64,
		op: &Operators,
		diagnostics: &mut [f64; 6],
	) -> Result<[f32; 5]> {
		let shift = (next_boundary - self.boundary) / H;
		let mut written = [self.p, self.q];
		let mut jump = [0.0; 2];
		for (channel, jumped) in written.iter_mut().zip(&mut jump) {
			let old = *channel;
			channel[..6].fill(0.0);
			let mut upper = 0.0;
			for (i, old_value) in old[..6].iter().enumerate() {
				let cdf = |j: usize| (shift + j as f64 - i as f64).clamp(0.0, 1.0);
				*jumped += old_value * cdf(0);
				upper += old_value * (1.0 - cdf(6));
				for (j, value) in channel[..6].iter_mut().enumerate() {
					*value += old_value * (cdf(j + 1) - cdf(j));
				}
			}
			channel[5] += upper;
			channel[6] += *jumped;
		}
		let probability = written[0];
		for (value, mass) in written[1][..6].iter_mut().zip(&probability[..6]) {
			*value = 0.5 * *value + 0.5 * mark * mass;
		}
		let mut result = [[0.0; 12]; 2];
		for (result_row, written_row) in result.iter_mut().zip(&written) {
			for (i, written_value) in written_row.iter().enumerate() {
				for (j, value) in result_row.iter_mut().enumerate() {
					*value += written_value * op.propagate.a[i * 12 + j];
				}
			}
		}
		self.p.copy_from_slice(&result[0][..10]);
		self.q.copy_from_slice(&result[1][..10]);
		let mut never_hit = written[0];
		never_hit[6] -= jump[0];
		let risk = jump[0]
			+ never_hit
				.iter()
				.zip(&op.first)
				.map(|(x, y)| x * y)
				.sum::<f64>();
		let continuation = self
			.p
			.iter()
			.zip(&op.value)
			.map(|(x, y)| x * y)
			.sum::<f64>();
		let margin = self.p[..6]
			.iter()
			.zip(centers())
			.map(|(x, y)| x * y)
			.sum::<f64>()
			/ 2.0;
		let hits = [jump[0] + result[0][10], jump[1] + result[1][10]];
		let current = [
			(self.p.iter().sum::<f64>() - 1.0).abs(),
			self.p.iter().map(|x| -*x).fold(0.0, f64::max),
			self.q
				.iter()
				.zip(self.p)
				.map(|(q, p)| q.abs() - p)
				.fold(0.0, f64::max),
			(-risk).max(0.0),
			(risk - 1.0).max(0.0),
			(risk - hits[0]).max(0.0),
		];
		ensure!(
			self.p.iter().chain(&self.q).all(|x| x.is_finite())
				&& current.iter().all(|x| x.is_finite() && *x <= TOLERANCE),
			"physical state invariant"
		);
		for (maximum, violation) in diagnostics.iter_mut().zip(current) {
			*maximum = maximum.max(violation);
		}
		self.boundary = next_boundary;
		let feature = [
			continuation as f32,
			risk as f32,
			(hits[1] / DT) as f32,
			(hits[0] / DT) as f32,
			margin as f32,
		];
		ensure!(feature.iter().all(|x| x.is_finite()), "nonfinite feature");
		Ok(feature)
	}
}
