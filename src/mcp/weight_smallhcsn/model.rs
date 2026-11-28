// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fixed-profile six-tick model; no cached activation enters this evaluator.
use super::deadline::Deadline;
use super::trace::{ResearchGraph, TickTrace};
use super::{
	bound_io::{BoundModel, Inputs},
	physics::{self, Operators, Population},
};
use anyhow::{ensure, Context, Result};

pub struct Output {
	pub n: usize,
	pub features: Vec<f32>,
	pub heads: Vec<f32>,
	pub scores: Vec<f32>,
	pub diagnostics: [f64; 6],
	pub mse: f64,
	pub correct: u32,
}
fn dot(x: &[f32], weights: &[f64]) -> f32 {
	let mut sum = 0.0f32;
	for (a, b) in x.iter().zip(weights) {
		sum += *a * (*b as f32);
	}
	sum
}
pub(super) fn evaluate(model: &BoundModel, inputs: &Inputs, deadline: &Deadline) -> Result<Output> {
	evaluate_inner(model, inputs, deadline, None, ResearchGraph::Original)
}

pub(super) fn evaluate_traced(
	model: &BoundModel,
	inputs: &Inputs,
	deadline: &Deadline,
) -> Result<(Output, Vec<TickTrace>)> {
	evaluate_research_traced(model, inputs, deadline, ResearchGraph::Original)
}

pub(super) fn evaluate_research_traced(
	model: &BoundModel,
	inputs: &Inputs,
	deadline: &Deadline,
	graph: ResearchGraph,
) -> Result<(Output, Vec<TickTrace>)> {
	let mut records = Vec::with_capacity(inputs.n * 2 * 6);
	let output = evaluate_inner(model, inputs, deadline, Some(&mut records), graph)?;
	Ok((output, records))
}

fn evaluate_inner(
	model: &BoundModel,
	inputs: &Inputs,
	deadline: &Deadline,
	mut records: Option<&mut Vec<TickTrace>>,
	graph: ResearchGraph,
) -> Result<Output> {
	deadline.check()?;
	let w = &model.tensors;
	let fixed = &w["body.fixed_boundary"];
	let absolute = &w["body.reset_absolute"];
	let mut recurrent = [[0.0f32; 8]; 8];
	for (i, row) in recurrent.iter_mut().enumerate() {
		for (j, value) in row.iter_mut().enumerate() {
			*value = (w["body.recurrent.weight"][i * 24 + j] as f32)
				* (w["body.synaptic_mask"][i * 24 + j] as f32);
		}
	}
	let mut out = Output {
		n: inputs.n,
		features: vec![0.0; inputs.n * 40],
		heads: vec![0.0; inputs.n * 4],
		scores: vec![0.0; inputs.n * 2],
		diagnostics: [0.0; 6],
		mse: 0.0,
		correct: 0,
	};
	for query in 0..inputs.n {
		for choice in 0..2 {
			deadline.check()?;
			let mut states: Vec<_> = (0..8)
				.map(|i| Population::new(fixed[i], absolute[i]))
				.collect::<Result<_>>()?;
			let mut ops: Vec<Option<Operators>> = (0..8).map(|_| None).collect();
			let mut effective_drift = [0.0; 8];
			let mut effective_cost = [0.0; 8];
			for tick in 0..6 {
				deadline.check()?;
				let xbegin = ((query * 6 + tick) * 2 + choice) * 9;
				let x = &inputs.x[xbegin..xbegin + 9];
				let mut trace = records
					.as_ref()
					.map(|_| TickTrace::new(query, choice, tick, x));
				// Centering is the prior boundary minus its fixed nominal value.
				let message: [f32; 8] = std::array::from_fn(|j| {
					if tick == 0 {
						0.0
					} else {
						(states[j].boundary - fixed[j]) as f32
					}
				});
				if let Some(observation) = trace.as_mut() {
					observation.prior_centered_boundary = message;
				}
				for (i, state) in states.iter_mut().enumerate() {
					let mut rec = 0.0f32;
					for (value, weight) in message.iter().zip(&recurrent[i]) {
						rec += value * weight;
					}
					// The other sixteen recurrent input coordinates are exactly zero in boundary mode.
					let mut drive = rec;
					let mut raw_mark = rec;
					if i < 4 {
						drive = (dot(x, &w["body.input_drive.weight"][i * 9..i * 9 + 9])
							+ w["body.input_drive.bias"][i] as f32)
							+ rec;
						raw_mark = (dot(x, &w["body.input_mark.weight"][i * 9..i * 9 + 9])
							+ w["body.input_mark.bias"][i] as f32)
							+ rec;
					}
					if graph == ResearchGraph::FinalTickTiedReceiverMark && tick == 5 && i >= 4 {
						// This is a named changed graph: reuse the sender-mark row for its paired
						// receiver only at the final tick. No new parameter or QVI update is added.
						let sender = i - 4;
						raw_mark =
							(dot(x, &w["body.input_mark.weight"][sender * 9..sender * 9 + 9])
								+ w["body.input_mark.bias"][sender] as f32)
								+ rec;
					}
					let mut boundary = state.boundary;
					if let Some(observation) = trace.as_mut() {
						observation.recurrent_offset[i] = rec;
						observation.drive[i] = drive;
						observation.raw_mark[i] = raw_mark;
						observation.boundary_before[i] = boundary;
					}
					if tick % 2 == 0 {
						let drift = (-0.2f32 + 0.15f32 * drive.tanh()) as f64;
						let cost = (0.15f32
							+ 0.02f32 * (w["body.raw_cost"][i] as f32 + 0.15f32 * drive).tanh())
							as f64;
						boundary = physics::qvi(drift, cost, absolute[i])?;
						ops[i] = Some(physics::operators(drift, boundary, cost, absolute[i])?);
						effective_drift[i] = drift;
						effective_cost[i] = cost;
					}
					let mut affine = [0.0; 2];
					let operator = ops[i]
						.as_ref()
						.context("missing initialized physical operator")?;
					let feature = if trace.is_some() {
						state.flow_observed(
							boundary,
							raw_mark.tanh() as f64,
							operator,
							&mut out.diagnostics,
							Some(&mut affine),
						)?
					} else {
						state.flow(
							boundary,
							raw_mark.tanh() as f64,
							operator,
							&mut out.diagnostics,
						)?
					};
					if let Some(observation) = trace.as_mut() {
						observation.boundary_after[i] = state.boundary;
						observation.features[i] = feature;
						observation.signed_rate_mark_offset[i] = affine[0];
						observation.signed_rate_mark_slope[i] = affine[1];
					}
					if tick == 5 && i >= 4 {
						let begin = (query * 2 + choice) * 20 + (i - 4) * 5;
						out.features[begin..begin + 5].copy_from_slice(&feature);
					}
				}
				if let (Some(records), Some(mut observation)) = (records.as_mut(), trace) {
					observation.effective_drift = effective_drift;
					observation.effective_cost = effective_cost;
					let receiver: [f32; 20] =
						std::array::from_fn(|j| observation.features[4 + j / 5][j % 5]);
					for head in 0..2 {
						observation.receiver_heads[head] = dot(
							&receiver,
							&w["body.readout.weight"][head * 20..head * 20 + 20],
						) + w["body.readout.bias"][head] as f32;
					}
					observation.external_baseline = inputs.baseline[query * 2 + choice];
					observation.choice_score = observation.external_baseline
						+ (observation.receiver_heads[1] - observation.receiver_heads[0]);
					observation.cumulative_call_physical_residual_max = out.diagnostics;
					records.push(observation);
				}
			}
			let row = query * 2 + choice;
			for j in 0..2 {
				out.heads[row * 2 + j] = dot(
					&out.features[row * 20..row * 20 + 20],
					&w["body.readout.weight"][j * 20..j * 20 + 20],
				) + w["body.readout.bias"][j] as f32;
			}
			let contrast = out.heads[row * 2 + 1] - out.heads[row * 2];
			out.scores[row] = inputs.baseline[row] + contrast;
		}
	}
	for query in 0..inputs.n {
		let margin = out.scores[query * 2 + 1] - out.scores[query * 2];
		let residual = margin as f64 - (2.0 * inputs.labels[query] as f64 - 1.0);
		out.mse += residual * residual;
		// np.argmax selects choice zero on ties.
		let prediction = u8::from(out.scores[query * 2 + 1] > out.scores[query * 2]);
		out.correct += u32::from(prediction == inputs.labels[query]);
	}
	out.mse /= inputs.n as f64;
	deadline.check()?;
	ensure!(
		out.heads.iter().chain(&out.scores).all(|v| v.is_finite()) && out.mse.is_finite(),
		"nonfinite readout"
	);
	Ok(out)
}
impl Output {
	pub fn bytes(&self) -> Vec<u8> {
		let mut raw = b"HCSNOUT1".to_vec();
		raw.extend_from_slice(&(self.n as u32).to_le_bytes());
		raw.extend_from_slice(&20u32.to_le_bytes());
		for value in self.features.iter().chain(&self.heads).chain(&self.scores) {
			raw.extend_from_slice(&value.to_le_bytes());
		}
		for value in self.diagnostics.iter().chain(std::iter::once(&self.mse)) {
			raw.extend_from_slice(&value.to_le_bytes());
		}
		raw.extend_from_slice(&self.correct.to_le_bytes());
		raw
	}
}
