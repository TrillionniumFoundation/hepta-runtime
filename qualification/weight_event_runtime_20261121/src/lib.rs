// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Finite checkpoint CTMC event history; not a financial payoff or continuous diffusion.

use anyhow::{anyhow, bail, Result};
use hepta_continuation_runtime_study::source::VerifiedSource;
use hepta_continuation_runtime_study::task::{Public, State};
use hepta_semantic_source_adapter_study::{digest, unique_json};
use serde::Serialize;
use std::collections::BTreeMap;

pub const PROFILE: &str = "finite-checkpoint-renewal-history-163-f64-v2";
pub const LAW_SOURCE_SHA256: &str =
	"2e7f19a2534567e31370eea24dec096a309e4db4aa42770efbf544bed84bcf65";
const TOLERANCE: f64 = 2e-10;

/// Seven reachable event histories: no hit; lower/upper before reset;
/// lower/upper first after reset but no opposite hit; both in either order.
pub fn basis() -> Vec<(u8, usize)> {
	(0..7)
		.flat_map(|history| {
			(0..33).filter_map(move |latent| {
				let allowed = match history {
					0 => latent < 31,
					1 => latent == 31,
					2 => latent == 32,
					3 => latent != 32,
					4 => latent != 31,
					_ => true,
				};
				allowed.then_some((history, latent))
			})
		})
		.collect()
}

fn next_history(history: u8, target: usize, reset: bool) -> u8 {
	let history = match (history, reset) {
		(1, true) => 3,
		(2, true) => 4,
		_ => history,
	};
	match (history, target) {
		(0, 31) => 1,
		(0, 32) => 2,
		(3, 32) => 5,
		(4, 31) => 6,
		_ => history,
	}
}

#[derive(Clone)]
pub struct SparseGenerator {
	rows: Vec<Vec<(usize, f64)>>,
	rate: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Propagation {
	pub mass: Vec<f64>,
	pub terms: usize,
	pub omitted_tail_bound: f64,
	pub normalization_error: f64,
}

impl SparseGenerator {
	fn from_rates(rows: Vec<Vec<(usize, f64)>>, exits: Vec<f64>) -> Result<Self> {
		if rows.is_empty() || rows.len() != exits.len() || rows.len() > 256 {
			bail!("invalid bounded generator dimensions");
		}
		let rate = exits.iter().copied().fold(0.0, f64::max);
		if !rate.is_finite() || !(0.0..=500.0).contains(&rate) {
			bail!("uniformization rate outside frozen envelope");
		}
		let mut stochastic = Vec::new();
		for (i, outgoing) in rows.into_iter().enumerate() {
			let mut total = 0.0;
			for (j, value) in &outgoing {
				if *j >= exits.len() || *j == i || !value.is_finite() || *value < 0.0 {
					bail!("invalid tagged generator contribution");
				}
				total += value;
			}
			if (total - exits[i]).abs() > TOLERANCE || exits[i] < 0.0 {
				bail!("tagged contributions disagree with exit rate");
			}
			let mut row = vec![(
				i,
				if rate == 0.0 {
					1.0
				} else {
					1.0 - exits[i] / rate
				},
			)];
			if rate != 0.0 {
				row.extend(outgoing.into_iter().map(|(j, value)| (j, value / rate)));
			}
			stochastic.push(row);
		}
		Ok(Self {
			rows: stochastic,
			rate,
		})
	}

	pub fn propagate(&self, initial: &[f64], duration: f64) -> Result<Propagation> {
		if initial.len() != self.rows.len()
			|| initial.iter().any(|x| !x.is_finite() || *x < 0.0)
			|| !duration.is_finite()
			|| !(0.0..=2.0).contains(&duration)
		{
			bail!("invalid propagation state or model-time duration");
		}
		let total: f64 = initial.iter().sum();
		if (total - 1.0).abs() > TOLERANCE {
			bail!("initial joint probability is not normalized");
		}
		if duration == 0.0 || self.rate == 0.0 {
			return Ok(Propagation {
				mass: initial.to_vec(),
				terms: 1,
				omitted_tail_bound: 0.0,
				normalization_error: (total - 1.0).abs(),
			});
		}
		let z = self.rate * duration;
		if z > 500.0 {
			bail!("Poisson envelope exceeds frozen work budget");
		}
		let mut weight = (-z).exp();
		let mut term = initial.to_vec();
		let mut result: Vec<_> = term.iter().map(|x| weight * x).collect();
		for k in 0..1023 {
			let next_weight = weight * z / (k + 1) as f64;
			let ratio = z / (k + 2) as f64;
			let bound = if ratio < 1.0 {
				next_weight / (1.0 - ratio)
			} else {
				f64::INFINITY
			};
			if bound <= 1e-15 {
				let normalization_error = (result.iter().sum::<f64>() - 1.0).abs();
				if normalization_error > TOLERANCE
					|| result.iter().any(|x| !x.is_finite() || *x < 0.0)
				{
					bail!("uniformization violated probability contract");
				}
				return Ok(Propagation {
					mass: result,
					terms: k + 1,
					omitted_tail_bound: bound,
					normalization_error,
				});
			}
			let mut next = vec![0.0; initial.len()];
			for (i, value) in term.iter().enumerate() {
				for (j, rate) in &self.rows[i] {
					next[*j] += value * rate;
				}
			}
			term = next;
			weight = next_weight;
			for (value, x) in result.iter_mut().zip(&term) {
				*value += weight * x;
			}
		}
		bail!("uniformization term budget exhausted")
	}
}

#[derive(Clone, Debug, Serialize)]
pub struct Decoder {
	pub first_lower: f64,
	pub first_upper: f64,
	pub no_outer_hit: f64,
	pub reset_seen: f64,
	pub both_boundaries: f64,
	pub endpoint_above_zero: f64,
	pub endpoint_at_zero: f64,
	pub endpoint_below_zero: f64,
	pub current_endpoint_nonpositive_sign_score: f64,
	pub current_endpoint_positive_sign_score: f64,
}

pub struct EventLaw {
	basis: Vec<(u8, usize)>,
	generators: BTreeMap<i8, SparseGenerator>,
	confusion: [[f64; 2]; 2],
	pub checkpoint_sha256: String,
	pub generator_reconstruction_max_error: f64,
}

fn normal_bin(left: f64, right: f64, mean: f64, sigma: f64) -> f64 {
	// Eight-point Gauss-Legendre integrates the source's Gaussian reset bins.
	// The independent oracle uses scipy.special.ndtr instead of this quadrature.
	let nodes = [
		0.1834346424956498,
		0.525532409916329,
		0.7966664774136267,
		0.9602898564975363,
	];
	let weights = [
		0.362683783378362,
		0.3137066458778873,
		0.2223810344533745,
		0.1012285362903763,
	];
	let half = (right - left) / 2.0;
	let middle = (right + left) / 2.0;
	let mut total = 0.0;
	for (node, weight) in nodes.iter().zip(weights) {
		for sign in [-1.0, 1.0] {
			let x = (middle + sign * half * node - mean) / sigma;
			total += weight * (-0.5 * x * x).exp() / (sigma * std::f64::consts::TAU.sqrt());
		}
	}
	half * total
}

fn rebuild(raw: &[f64], drive: i8) -> Result<Vec<Vec<f64>>> {
	if raw.len() != 8 || raw.iter().any(|x| !x.is_finite()) {
		bail!("eight finite source raw coordinates required");
	}
	let sigmoid = |x: f64| 1.0 / (1.0 + (-x).exp());
	let b = 0.8 + 0.4 * sigmoid(raw[0]);
	let sigma = 0.35 + 0.45 * sigmoid(raw[1]);
	let mu = 0.2 * raw[3].tanh() + 0.9 * raw[2].tanh() * f64::from(drive);
	let spacing = 2.0 * b / 32.0;
	let up = sigma * sigma / (2.0 * spacing * spacing) + mu / (2.0 * spacing);
	let down = sigma * sigma / (2.0 * spacing * spacing) - mu / (2.0 * spacing);
	if up <= 0.0 || down <= 0.0 {
		bail!("source positive-rate envelope failed");
	}
	let mut q = vec![vec![0.0; 33]; 33];
	for (i, row) in q.iter_mut().enumerate().take(31) {
		row[if i + 1 < 31 { i + 1 } else { 32 }] = up;
		row[if i > 0 { i - 1 } else { 31 }] = down;
		row[i] = -up - down;
	}
	let rate = 0.25 + 1.75 * sigmoid(raw[6]);
	let sd = b * (0.06 + 0.06 * sigmoid(raw[7]));
	for (index, coordinate) in [(31, 5), (32, 4)] {
		let mean = 0.6 * b * raw[coordinate].tanh();
		let mut bins = Vec::new();
		for i in 0..31 {
			let left = if i == 0 {
				-b
			} else {
				b * (-0.96875 + i as f64 / 16.0)
			};
			let right = if i == 30 {
				b
			} else {
				b * (-0.90625 + i as f64 / 16.0)
			};
			bins.push(normal_bin(left, right, mean, sd));
		}
		let total: f64 = bins.iter().sum();
		for (i, value) in bins.iter().enumerate() {
			q[index][i] = rate * value / total;
		}
		q[index][index] = -rate;
	}
	Ok(q)
}

impl EventLaw {
	pub fn authenticate(
		source: &VerifiedSource,
		decoded: &[u8],
		law_source: &[u8],
	) -> Result<Self> {
		if digest(decoded) != source.receipt().decoded_sha256
			|| digest(law_source) != LAW_SOURCE_SHA256
		{
			bail!("event model or reviewed decomposition source differs");
		}
		let model = unique_json(decoded)?;
		let raw: Vec<f64> = serde_json::from_value(model["core"]["raw"].clone())?;
		let confusion: [[f64; 2]; 2] = serde_json::from_value(model["confusion"].clone())?;
		let stored = model["core"]["generators"]
			.as_object()
			.ok_or_else(|| anyhow!("missing original generators"))?;
		if stored.len() != 3 {
			bail!("expected three frozen drive generators");
		}
		let basis = basis();
		let indices: BTreeMap<_, _> = basis
			.iter()
			.enumerate()
			.map(|(i, pair)| (*pair, i))
			.collect();
		let mut generators = BTreeMap::new();
		let mut error: f64 = 0.0;
		for drive in [-1, 0, 1] {
			let q: Vec<Vec<f64>> = serde_json::from_value(
				stored
					.get(&drive.to_string())
					.ok_or_else(|| anyhow!("missing drive"))?
					.clone(),
			)?;
			let reconstructed = rebuild(&raw, drive)?;
			if q.len() != 33 || q.iter().any(|row| row.len() != 33) {
				bail!("generator dimension mismatch");
			}
			for (actual, expected) in q.iter().flatten().zip(reconstructed.iter().flatten()) {
				if !actual.is_finite() {
					bail!("nonfinite source generator");
				}
				if *expected == 0.0 && *actual != 0.0 {
					bail!("stored generator introduces an unclassified transition contribution");
				}
				error = error.max((actual - expected).abs());
			}
			if error > TOLERANCE {
				bail!(
					"stored generator does not match source-derived diffusion/reset decomposition"
				);
			}
			let mut rows = Vec::new();
			let mut exits = Vec::new();
			for &(history, latent) in &basis {
				let mut row = Vec::new();
				for (target, &contribution) in q[latent].iter().enumerate() {
					if target == latent || contribution == 0.0 {
						continue;
					}
					// The verified source decomposition puts reset contributions only
					// in reference-to-interior rows. This is not a jump-distance heuristic.
					let reset = latent >= 31 && target < 31;
					let next = next_history(history, target, reset);
					let id = *indices
						.get(&(next, target))
						.ok_or_else(|| anyhow!("event transition left legal history basis"))?;
					row.push((id, contribution));
				}
				rows.push(row);
				exits.push(-q[latent][latent]);
			}
			generators.insert(drive, SparseGenerator::from_rates(rows, exits)?);
		}
		Ok(Self {
			basis,
			generators,
			confusion,
			checkpoint_sha256: source.receipt().compressed_sha256.clone(),
			generator_reconstruction_max_error: error,
		})
	}

	pub fn prior(&self, distance: f64) -> Result<Vec<f64>> {
		if ![0.125, 0.375, 0.75].contains(&distance) {
			bail!("unknown original prior");
		}
		let mut mass = vec![0.0; self.basis.len()];
		for sign in [-1.0, 1.0] {
			let index = (0..31)
				.min_by(|a, b| {
					((-0.9375 + *a as f64 / 16.0) - sign * distance)
						.abs()
						.total_cmp(&((-0.9375 + *b as f64 / 16.0) - sign * distance).abs())
				})
				.ok_or_else(|| anyhow!("empty basis"))?;
			mass[index] += 0.5;
		}
		Ok(mass)
	}
	pub fn propagate(&self, mass: &[f64], duration: f64, drive: i8) -> Result<Propagation> {
		self.generators
			.get(&drive)
			.ok_or_else(|| anyhow!("unknown drive"))?
			.propagate(mass, duration)
	}
	pub fn observe(&self, mass: &mut [f64], reliability: f64, observation: u8) -> Result<f64> {
		if mass.len() != self.basis.len()
			|| observation > 1
			|| !reliability.is_finite()
			|| !(0.5..=1.0).contains(&reliability)
			|| mass.iter().any(|value| !value.is_finite() || *value < 0.0)
			|| (mass.iter().sum::<f64>() - 1.0).abs() > TOLERANCE
		{
			bail!("invalid joint observation");
		}
		let mut next = mass.to_vec();
		let mut likelihood = 0.0;
		for (value, &(_, latent)) in next.iter_mut().zip(&self.basis) {
			let positive = (16..31).contains(&latent) || latent == 32;
			let noise = if positive {
				[1.0 - reliability, reliability]
			} else {
				[reliability, 1.0 - reliability]
			};
			let emission = noise[0] * self.confusion[0][observation as usize]
				+ noise[1] * self.confusion[1][observation as usize];
			*value *= emission;
			likelihood += *value;
		}
		if !likelihood.is_finite() || likelihood <= 0.0 {
			bail!("impossible observation");
		}
		for value in &mut next {
			*value /= likelihood;
		}
		mass.copy_from_slice(&next);
		Ok(likelihood)
	}
	pub fn belief(&self, public: &Public, state: &State) -> Result<Vec<f64>> {
		public.validate()?;
		hepta_continuation_runtime_study::task::validate_state(public, state)?;
		let mut mass = self.prior(public.prior_distance)?;
		for tick in 0..state.tick {
			mass = self
				.propagate(&mass, public.duration[tick], public.drive[tick])?
				.mass;
			if let Some(obs) = state
				.history
				.iter()
				.find(|r| r.observation_tick == tick + 1)
			{
				self.observe(&mut mass, obs.reliability, obs.observation)?;
			}
		}
		Ok(mass)
	}
	pub fn decode(&self, mass: &[f64], decoder: &str) -> Result<Decoder> {
		if decoder != "FIRST_OUTER_HISTORY_AND_CURRENT_ENDPOINT_SIGN_SCORE"
			|| mass.len() != self.basis.len()
		{
			bail!("unknown decoder; FinancialCallPut has no authenticated payoff contract");
		}
		let mut out = Decoder {
			first_lower: 0.0,
			first_upper: 0.0,
			no_outer_hit: 0.0,
			reset_seen: 0.0,
			both_boundaries: 0.0,
			endpoint_above_zero: 0.0,
			endpoint_at_zero: 0.0,
			endpoint_below_zero: 0.0,
			current_endpoint_nonpositive_sign_score: 0.0,
			current_endpoint_positive_sign_score: 0.0,
		};
		for (&value, &(history, latent)) in mass.iter().zip(&self.basis) {
			if !value.is_finite() || value < 0.0 {
				bail!("invalid joint mass");
			}
			match history {
				0 => out.no_outer_hit += value,
				1 | 3 | 5 => out.first_lower += value,
				_ => out.first_upper += value,
			}
			if history >= 3 {
				out.reset_seen += value;
			}
			if history >= 5 {
				out.both_boundaries += value;
			}
			if latent == 15 {
				out.endpoint_at_zero += value;
			} else if (16..31).contains(&latent) || latent == 32 {
				out.endpoint_above_zero += value;
			} else {
				out.endpoint_below_zero += value;
			}
		}
		if (out.first_lower + out.first_upper + out.no_outer_hit - 1.0).abs() > TOLERANCE {
			bail!("decoder probability partition failed");
		}
		// These scores concern only the supplied current endpoint distribution.
		// They do not forecast the task's fixed deadline and are not SUBMIT Q.
		out.current_endpoint_nonpositive_sign_score = 1.0 - 2.0 * out.endpoint_above_zero;
		out.current_endpoint_positive_sign_score = 2.0 * out.endpoint_above_zero - 1.0;
		Ok(out)
	}
}

#[cfg(test)]
#[path = "event_tests.rs"]
mod event_tests;
