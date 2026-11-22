// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Native complete-state enumeration, own-law Bellman recurrence and policy occupancy.

use crate::forward;
use anyhow::{anyhow, bail, Result};
use hepta_continuation_runtime_study::{
	source::VerifiedSource,
	task::{self, Public, State},
};
use hepta_semantic_source_adapter_study::digest;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Serialize)]
pub struct Edge {
	pub probability: f64,
	pub target: usize,
	pub fee: f64,
}

pub struct Graph {
	pub key: String,
	pub public: Public,
	pub states: Vec<State>,
	pub masks: Vec<[bool; 6]>,
	pub posterior: Vec<f64>,
	pub edges: Vec<[Vec<Edge>; 6]>,
	pub order: Vec<usize>,
	pub initial: usize,
	pub x: Vec<Vec<f64>>,
	pub hidden: Vec<Vec<f64>>,
	pub qstar: Vec<[f64; 6]>,
	pub optimum: Vec<f64>,
}

fn state_key(state: &State) -> Result<Vec<u8>> {
	Ok(serde_json::to_vec(state)?)
}

pub fn cache_key(
	protected: &str,
	public: &Public,
	initial: &State,
	hardware: &str,
) -> Result<String> {
	Ok(digest(&serde_json::to_vec(
		&json!({"protected_model_and_law":protected,"public":public,
		"complete_initial_state":initial,"horizon":6,"arithmetic":forward::ARITHMETIC,"hardware":hardware}),
	)?))
}

pub fn check_cache(
	graph: &Graph,
	protected: &str,
	public: &Public,
	initial: &State,
	hardware: &str,
) -> Result<()> {
	if graph.key != cache_key(protected, public, initial, hardware)? {
		bail!("cache law/schedule/state/arithmetic/hardware key differs");
	}
	Ok(())
}

pub fn build(
	source: &VerifiedSource,
	model: &Value,
	public: &Public,
	hardware: &str,
) -> Result<Graph> {
	source.validate_schedule(public)?;
	let initial_state = task::initial(public)?;
	let key = cache_key(
		&source.receipt().protected_fields_sha256,
		public,
		&initial_state,
		hardware,
	)?;
	let mut pending = vec![initial_state.clone()];
	let mut index = BTreeMap::new();
	let mut states = Vec::new();
	while let Some(state) = pending.pop() {
		let identity = state_key(&state)?;
		if index.contains_key(&identity) {
			continue;
		}
		if states.len() >= 4096 {
			bail!("full DAG state cap exceeded");
		}
		task::validate_state(public, &state)?;
		index.insert(identity, states.len());
		states.push(state.clone());
		for action in 1..4 {
			if task::legal(public, &state)[action] {
				for completion in task::completions(public, &state, action)? {
					pending.push(task::successor(public, &state, action, completion)?);
				}
			}
		}
	}
	let n = states.len();
	let mut posterior = Vec::with_capacity(n);
	let mut masks = Vec::with_capacity(n);
	let mut edges = Vec::with_capacity(n);
	let mut x = Vec::with_capacity(n);
	let mut hidden = Vec::with_capacity(n);
	let mut edge_count = 0;
	for state in &states {
		let p = source.endpoint_posterior(public, state)?;
		if !p.is_finite() || !(0.0..=1.0).contains(&p) {
			bail!("invalid independently derived posterior");
		}
		posterior.push(p);
		let mask = task::legal(public, state);
		masks.push(mask);
		let mut row: [Vec<Edge>; 6] = std::array::from_fn(|_| Vec::new());
		for (action, outgoing) in row.iter_mut().enumerate().take(4).skip(1) {
			if !mask[action] {
				continue;
			}
			for completion in task::completions(public, state, action)? {
				let after = task::successor(public, state, action, completion)?;
				let probability = source.completion_probability(public, state, completion)?;
				let fee = after.charges - state.charges;
				if after.tick != state.tick + 1
					|| !probability.is_finite()
					|| !(0.0..=1.0).contains(&probability)
					|| fee < 0.0
				{
					bail!("invalid native transition");
				}
				let target = *index
					.get(&state_key(&after)?)
					.ok_or_else(|| anyhow!("incomplete structural graph"))?;
				outgoing.push(Edge {
					probability,
					target,
					fee,
				});
				edge_count += 1;
			}
			if (outgoing.iter().map(|e| e.probability).sum::<f64>() - 1.0).abs() > 2e-11 {
				bail!("native mass normalization failed; no renormalization allowed");
			}
		}
		if edge_count > 36864 {
			bail!("full DAG edge cap exceeded");
		}
		edges.push(row);
		let mut input = forward::public_features(public, state);
		input.extend(source.representation(public, state)?);
		hidden.push(forward::hidden(model, &input)?);
		x.push(input);
	}
	let mut order: Vec<_> = (0..n).collect();
	order.sort_by_key(|i| states[*i].tick);
	let initial = *index
		.get(&state_key(&initial_state)?)
		.ok_or_else(|| anyhow!("missing initial state"))?;
	let mut qstar = vec![[0.0; 6]; n];
	let mut optimum = vec![0.0; n];
	for &i in order.iter().rev() {
		qstar[i] = [
			0.0,
			0.0,
			0.0,
			0.0,
			1.0 - 2.0 * posterior[i],
			2.0 * posterior[i] - 1.0,
		];
		for (action, row) in edges[i].iter().enumerate().take(4).skip(1) {
			for e in row {
				if e.probability != 0.0 {
					qstar[i][action] += e.probability * (optimum[e.target] - e.fee);
				}
			}
		}
		optimum[i] = qstar[i][choose(qstar[i], masks[i])];
	}
	Ok(Graph {
		key,
		public: public.clone(),
		states,
		masks,
		posterior,
		edges,
		order,
		initial,
		x,
		hidden,
		qstar,
		optimum,
	})
}

pub fn choose(scores: [f64; 6], mask: [bool; 6]) -> usize {
	let mut action = 0;
	for (i, legal) in mask.iter().enumerate() {
		if *legal && scores[i] > scores[action] {
			action = i;
		}
	}
	action
}

#[derive(Serialize)]
pub struct Evaluation {
	pub utility: f64,
	pub optimal_utility: f64,
	pub expected_terminal_reward: f64,
	pub expected_expense: f64,
	pub terminal_gap_contribution: f64,
	pub continuation_gap_contribution: f64,
	pub terminal_mass: f64,
	pub pdi_residual: f64,
	pub expected_decisions: f64,
	pub actions: Vec<usize>,
	pub values: Vec<f64>,
	pub occupancy: Vec<f64>,
	pub scores: Vec<[f64; 6]>,
}

pub fn evaluate(graph: &Graph, readout: &[f64; 196]) -> Result<Evaluation> {
	let scores = graph
		.hidden
		.iter()
		.map(|h| forward::scores(readout, h))
		.collect::<Result<Vec<_>>>()?;
	evaluate_scores(graph, scores)
}

pub fn evaluate_scores(g: &Graph, scores: Vec<[f64; 6]>) -> Result<Evaluation> {
	let n = g.states.len();
	if scores.len() != n || scores.iter().flatten().any(|s| !s.is_finite()) {
		bail!("complete finite native score array required");
	}
	let actions: Vec<_> = scores
		.iter()
		.zip(&g.masks)
		.map(|(s, m)| choose(*s, *m))
		.collect();
	let mut values = vec![0.0; n];
	let mut occupancy = vec![0.0; n];
	for &i in g.order.iter().rev() {
		let a = actions[i];
		if [0, 4, 5].contains(&a) {
			values[i] = g.qstar[i][a];
		} else {
			for e in &g.edges[i][a] {
				if e.probability != 0.0 {
					let successor_value = values[e.target];
					values[i] += e.probability * (successor_value - e.fee);
				}
			}
		}
	}
	occupancy[g.initial] = 1.0;
	for &i in &g.order {
		for e in &g.edges[i][actions[i]] {
			if e.probability != 0.0 {
				let source_occupancy = occupancy[i];
				occupancy[e.target] += source_occupancy * e.probability;
			}
		}
	}
	let (mut terminal_gap, mut continuation_gap, mut reward, mut expense, mut terminal_mass) =
		(0.0, 0.0, 0.0, 0.0, 0.0);
	for &i in &g.order {
		let a = actions[i];
		let gap = g.optimum[i] - g.qstar[i][a];
		if gap < -2e-12 {
			bail!("negative native optimal-action gap");
		}
		if [0, 4, 5].contains(&a) {
			terminal_gap += occupancy[i] * gap;
			reward += occupancy[i] * g.qstar[i][a];
			terminal_mass += occupancy[i];
		} else {
			continuation_gap += occupancy[i] * gap;
			for e in &g.edges[i][a] {
				expense += occupancy[i] * e.probability * e.fee;
			}
		}
	}
	let utility = values[g.initial];
	let optimal_utility = g.optimum[g.initial];
	let residual = optimal_utility - utility - terminal_gap - continuation_gap;
	let tolerance = 1e-10
		* (1.0 + utility.abs() + optimal_utility.abs() + (terminal_gap + continuation_gap).abs());
	if (terminal_mass - 1.0).abs() > 2e-10
		|| residual.abs() > tolerance
		|| (utility - reward + expense).abs() > tolerance
	{
		bail!("native complete task identities failed");
	}
	Ok(Evaluation {
		utility,
		optimal_utility,
		expected_terminal_reward: reward,
		expected_expense: expense,
		terminal_gap_contribution: terminal_gap,
		continuation_gap_contribution: continuation_gap,
		terminal_mass,
		pdi_residual: residual,
		expected_decisions: occupancy.iter().sum(),
		actions,
		values,
		occupancy,
		scores,
	})
}
