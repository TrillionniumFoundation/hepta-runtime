// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Independent native results compared with already exposed original records.

use crate::dag::{Evaluation, Graph};
use anyhow::{bail, Result};
use hepta_continuation_runtime_study::task::{Public, State};
use serde_json::{json, Value};
type ReferenceEdges = Vec<Vec<Vec<(f64, usize, f64)>>>;

pub fn numbers(actual: &[f64], expected: &[f64], tolerance: f64) -> Result<f64> {
	if actual.len() != expected.len() {
		bail!("complete numeric array shape differs");
	}
	let mut maximum: f64 = 0.0;
	for (a, b) in actual.iter().zip(expected) {
		let error = (a - b).abs();
		maximum = maximum.max(error);
		if !a.is_finite() || !b.is_finite() || error > tolerance * (1.0 + b.abs()) {
			bail!("native/reference arithmetic exceeds frozen tolerance: {error}");
		}
	}
	Ok(maximum)
}

fn matrix(actual: &[Vec<f64>], expected: &Value, tolerance: f64) -> Result<f64> {
	let expected: Vec<Vec<f64>> = serde_json::from_value(expected.clone())?;
	if actual.len() != expected.len()
		|| actual
			.iter()
			.zip(&expected)
			.any(|(a, b)| a.len() != b.len())
	{
		bail!("complete matrix dimensions differ");
	}
	numbers(
		&actual.iter().flatten().copied().collect::<Vec<_>>(),
		&expected.iter().flatten().copied().collect::<Vec<_>>(),
		tolerance,
	)
}

pub fn graph(actual: &Graph, reference: &Value) -> Result<Value> {
	let g = &reference["graph"];
	let states: Vec<State> = serde_json::from_value(g["states"].clone())?;
	let masks: Vec<[bool; 6]> = serde_json::from_value(g["masks"].clone())?;
	let public: Public = serde_json::from_value(g["public"].clone())?;
	let order: Vec<usize> = serde_json::from_value(g["order"].clone())?;
	if actual.states != states
		|| actual.masks != masks
		|| actual.public != public
		|| actual.order != order
		|| g["initial"] != actual.initial
	{
		bail!("independently enumerated complete state DAG differs");
	}
	let posterior: Vec<f64> = serde_json::from_value(g["posterior"].clone())?;
	let posterior_error = numbers(&actual.posterior, &posterior, 2e-11)?;
	let x_error = matrix(&actual.x, &reference["X"], 2e-12)?;
	let hidden_error = matrix(&actual.hidden, &reference["H"], 2e-12)?;
	let q: Vec<Vec<f64>> = actual.qstar.iter().map(|v| v.to_vec()).collect();
	let q_error = matrix(&q, &g["qstar"], 2e-11)?;
	let expected_edges: ReferenceEdges = serde_json::from_value(g["edges"].clone())?;
	if expected_edges.len() != actual.edges.len() {
		bail!("full edge graph dimensions differ");
	}
	let mut probability_error: f64 = 0.0;
	let mut edges = 0;
	for (actual_row, expected_row) in actual.edges.iter().zip(expected_edges) {
		if expected_row.len() != 3 {
			bail!("three continuation edge columns required");
		}
		for (action, outgoing) in actual_row.iter().enumerate().take(4).skip(1) {
			if outgoing.len() != expected_row[action - 1].len() {
				bail!("missing independent structural branch");
			}
			for (a, (p, target, fee)) in outgoing.iter().zip(&expected_row[action - 1]) {
				if a.target != *target || a.fee.to_bits() != fee.to_bits() {
					bail!("native transition target/fee bits differ");
				}
				probability_error = probability_error.max(numbers(&[a.probability], &[*p], 2e-11)?);
				edges += 1;
			}
		}
	}
	Ok(
		json!({"states":actual.states.len(),"edges":edges,"complete_states_masks_order_and_fees_exact":true,
		"posterior_max_abs_error":posterior_error,"X_max_abs_error":x_error,"hidden_max_abs_error":hidden_error,
		"own_optimal_Q_max_abs_error":q_error,"probability_max_abs_error":probability_error,
		"cache_key":actual.key,"full_DAG_independently_recomputed":true,"raw_CTMC_exponentials_recomputed":false}),
	)
}

pub fn policy(actual: &Evaluation, reference: &Value) -> Result<Value> {
	let actions: Vec<usize> = serde_json::from_value(reference["actions"].clone())?;
	if actions != actual.actions {
		bail!("native/reference policy actions differ; no tolerance-based action substitution");
	}
	let scores: Vec<Vec<f64>> = actual.scores.iter().map(|v| v.to_vec()).collect();
	let score_error = matrix(&scores, &reference["scores"], 2e-12)?;
	let values: Vec<f64> = serde_json::from_value(reference["values"].clone())?;
	let occupancy: Vec<f64> = serde_json::from_value(reference["occupancy"].clone())?;
	let value_error = numbers(&actual.values, &values, 2e-11)?;
	let occupancy_error = numbers(&actual.occupancy, &occupancy, 2e-11)?;
	let metrics = &reference["metrics"];
	let native = [
		actual.utility,
		actual.optimal_utility,
		actual.expected_terminal_reward,
		actual.expected_expense,
		actual.terminal_gap_contribution,
		actual.continuation_gap_contribution,
		actual.terminal_mass,
		actual.expected_decisions,
	];
	let names = [
		"utility",
		"optimal_utility",
		"expected_terminal_reward",
		"expected_expense",
		"terminal_gap_contribution",
		"continuation_gap_contribution",
		"terminal_mass",
		"expected_decisions",
	];
	let expected = names
		.iter()
		.map(|name| serde_json::from_value::<f64>(metrics[*name].clone()))
		.collect::<std::result::Result<Vec<_>, _>>()?;
	let metrics_error = numbers(&native, &expected, 2e-11)?;
	Ok(
		json!({"all_actions_exact":true,"score_max_abs_error":score_error,"value_array_max_abs_error":value_error,
		"occupancy_max_abs_error":occupancy_error,"metric_max_abs_error":metrics_error,"native_utility":actual.utility,
		"original_record_utility":expected[0],"terminal_gap_contribution":actual.terminal_gap_contribution,
		"continuation_gap_contribution":actual.continuation_gap_contribution,"PDI_residual":actual.pdi_residual,
		"role":"arithmetic_and_complete_task_semantic_conformance_only","new_quality_comparison":false}),
	)
}
