// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Read-only observations of the existing full-model rollout, not causal attribution.

use serde::{Deserialize, Serialize};

/// Scientific graph controls are explicit and never selected by normal evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchGraph {
	Original,
	FinalTickTiedReceiverMark,
}

/// One completed choice/tick. Effective drift and cost persist between QVI refreshes.
/// The last residual field is the maximum seen in the complete call so far, not a
/// per-neuron residual. Records never replace state, messages or model inputs.
#[derive(Clone, Debug, Serialize)]
pub struct TickTrace {
	pub query: usize,
	pub choice: usize,
	pub tick: usize,
	pub qvi_refreshed: bool,
	pub normalized_input: [f32; 9],
	pub prior_centered_boundary: [f32; 8],
	pub recurrent_offset: [f32; 8],
	pub drive: [f32; 8],
	pub raw_mark: [f32; 8],
	pub effective_drift: [f64; 8],
	pub effective_cost: [f64; 8],
	pub boundary_before: [f64; 8],
	pub boundary_after: [f64; 8],
	pub features: [[f32; 5]; 8],
	/// The F64 signed-rate expression before its final F32 conversion. These coefficients
	/// fix the pre-flow population and physical operator; they are not across-time derivatives.
	pub signed_rate_mark_offset: [f64; 8],
	pub signed_rate_mark_slope: [f64; 8],
	pub receiver_heads: [f32; 2],
	pub external_baseline: f32,
	pub choice_score: f32,
	pub cumulative_call_physical_residual_max: [f64; 6],
}

impl TickTrace {
	pub(super) fn new(query: usize, choice: usize, tick: usize, input: &[f32]) -> Self {
		Self {
			query,
			choice,
			tick,
			qvi_refreshed: tick.is_multiple_of(2),
			normalized_input: std::array::from_fn(|i| input[i]),
			prior_centered_boundary: [0.0; 8],
			recurrent_offset: [0.0; 8],
			drive: [0.0; 8],
			raw_mark: [0.0; 8],
			effective_drift: [0.0; 8],
			effective_cost: [0.0; 8],
			boundary_before: [0.0; 8],
			boundary_after: [0.0; 8],
			features: [[0.0; 5]; 8],
			signed_rate_mark_offset: [0.0; 8],
			signed_rate_mark_slope: [0.0; 8],
			receiver_heads: [0.0; 2],
			external_baseline: 0.0,
			choice_score: 0.0,
			cumulative_call_physical_residual_max: [0.0; 6],
		}
	}
}
