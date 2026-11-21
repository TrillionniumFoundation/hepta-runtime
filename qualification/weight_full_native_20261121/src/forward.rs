// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! The explicit F64 85-to-48-to-4 contract, with a separately named arithmetic version.

use anyhow::{bail, Result};
use hepta_continuation_runtime_study::task::{Public, State};
use serde_json::Value;

pub const ARITHMETIC: &str = "native-f64-ordered-law-numpy-pairwise128-v1";

pub fn sum(values: &[f64]) -> f64 {
	if values.len() < 8 {
		return values.iter().fold(-0.0, |a, b| a + b);
	}
	if values.len() > 128 {
		let half = (values.len() / 2) & !7;
		return sum(&values[..half]) + sum(&values[half..]);
	}
	let mut lane: [f64; 8] = std::array::from_fn(|i| values[i]);
	let end = values.len() - values.len() % 8;
	for chunk in values[8..end].chunks_exact(8) {
		for (accumulator, value) in lane.iter_mut().zip(chunk) {
			*accumulator += value;
		}
	}
	let initial =
		((lane[0] + lane[1]) + (lane[2] + lane[3])) + ((lane[4] + lane[5]) + (lane[6] + lane[7]));
	values[end..].iter().fold(initial, |a, b| a + b)
}

pub fn public_features(public: &Public, state: &State) -> Vec<f64> {
	let mut x = vec![
		state.tick as f64 / 6.0,
		state.budget as f64 / 3.0,
		state.elapsed / 9.0,
		state.charges,
		u8::from(state.broken) as f64,
		u8::from(state.pending.is_some()) as f64,
		state
			.pending
			.as_ref()
			.map_or(0.0, |p| (p.due_tick - state.tick) as f64 / 2.0),
		f64::from(state.last_symbol),
		state.last_reliability,
		public.latency_price,
		public.repair_price,
		public.failure_probability,
	];
	for i in 0..6 {
		x.extend([
			public.duration[i] / 2.0,
			public.reliability[i],
			public.read_price[i],
			public.read_delay[i] as f64 / 2.0,
		]);
	}
	x.extend(public.drive.map(f64::from));
	x.push(public.prior_distance);
	x
}

pub fn hidden(model: &Value, x: &[f64]) -> Result<Vec<f64>> {
	let w: Vec<Vec<f64>> = serde_json::from_value(model["network"]["w1"].clone())?;
	let b: Vec<f64> = serde_json::from_value(model["network"]["b1"].clone())?;
	if x.len() != 85 || w.len() != 48 || b.len() != 48 || w.iter().any(|r| r.len() != 85) {
		bail!("full hidden shape differs");
	}
	let mut out = Vec::with_capacity(49);
	for (row, bias) in w.iter().zip(b) {
		let products: Vec<_> = row.iter().zip(x).map(|(a, b)| a * b).collect();
		out.push((sum(&products) + bias).tanh());
	}
	out.push(1.0);
	if out.iter().any(|x| !x.is_finite()) {
		bail!("nonfinite hidden representation");
	}
	Ok(out)
}

pub fn scores(readout: &[f64; 196], h: &[f64]) -> Result<[f64; 6]> {
	if h.len() != 49 {
		bail!("readout requires all 49 augmented hidden coordinates");
	}
	let z: [f64; 4] = std::array::from_fn(|row| {
		let mut products: Vec<_> = readout[row * 48..(row + 1) * 48]
			.iter()
			.zip(h)
			.map(|(a, b)| a * b)
			.collect();
		products.push(readout[192 + row] * h[48]);
		sum(&products)
	});
	let p = 1.0 / (1.0 + (-z[3].clamp(-700.0, 700.0)).exp());
	let out = [0.0, z[0], z[1], z[2], 1.0 - 2.0 * p, 2.0 * p - 1.0];
	if out.iter().any(|x| !x.is_finite()) {
		bail!("nonfinite head score");
	}
	Ok(out)
}
