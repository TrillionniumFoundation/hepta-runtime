// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Improve a supplied policy uniformly over a common scalar settlement-fee interval.
//! Probabilities, legal actions and terminal rewards must be shared across the interval.
use super::{Graph, Outcome, State, ACTIONS, TOLERANCE};

type Endpoints = [f64; 2];

fn q(state: &State, action: usize, children: &[Endpoints], factors: Endpoints) -> Endpoints {
	if !(1..=3).contains(&action) {
		return [state.terminal[action]; 2];
	}
	std::array::from_fn(|k| {
		state.branches[action - 1]
			.iter()
			.map(|e| e.probability * (children[e.next][k] - factors[k] * e.fee))
			.sum()
	})
}

pub(super) fn evaluate(graph: &Graph, policy: &[usize], factors: Endpoints) -> Vec<Endpoints> {
	let mut result = vec![[0.; 2]; graph.states.len()];
	for &i in graph.order.iter().rev() {
		result[i] = q(&graph.states[i], policy[i], &result, factors);
	}
	result
}

fn improvement(x: Endpoints, anchor: Endpoints) -> f64 {
	(x[0] - anchor[0]).min(x[1] - anchor[1])
}

pub(super) fn validate(graph: &Graph, factors: Endpoints) -> Outcome<()> {
	if !factors.iter().all(|x| x.is_finite() && *x >= 0.) || factors[0] > factors[1] {
		return Err("require finite ordered nonnegative fee multipliers".into());
	}
	let max_fee = graph.max_fee * factors[1];
	if !max_fee.is_finite() || max_fee > f64::MAX / (8. * (graph.deadline as f64 + 1.)) {
		return Err("fee band exceeds the numerical range".into());
	}
	Ok(())
}

fn solve(
	graph: &Graph,
	factors: Endpoints,
	restrict: bool,
	backward: bool,
) -> Outcome<(Vec<usize>, Endpoints)> {
	validate(graph, factors)?;
	let mut policy: Vec<_> = graph.states.iter().map(|s| s.original).collect();
	let base = evaluate(graph, &policy, factors);
	let mut values = base.clone();
	for &i in graph.order.iter().rev() {
		let state = &graph.states[i];
		let continuation = if backward { &values } else { &base };
		let mut chosen = state.original;
		let mut best = q(state, chosen, continuation, factors);
		for action in 0..ACTIONS {
			if !state.legal(action)
				|| action == state.original
				|| (restrict && action != state.direct)
			{
				continue;
			}
			let candidate = q(state, action, continuation, factors);
			if improvement(candidate, base[i]) > improvement(best, base[i]) + TOLERANCE {
				best = candidate;
				chosen = action;
			}
		}
		policy[i] = chosen;
		values[i] = best;
	}
	// Verify the complete committed policy at both endpoints for every state.
	let final_values = evaluate(graph, &policy, factors);
	for (v, b) in final_values.iter().zip(&base) {
		if !v.iter().chain(b).all(|x| x.is_finite()) || improvement(*v, *b) < -TOLERANCE {
			return Err("complete policy failed the fee endpoint comparison".into());
		}
	}
	Ok((policy, final_values[graph.initial]))
}

pub(super) fn emit(graph: &Graph, lo: f64, hi: f64) -> Outcome<()> {
	for (name, restrict, backward) in [
		("BAND_ONE_DIRECT", true, false),
		("BAND_BACK_DIRECT", true, true),
		("BAND_ONE_ALL", false, false),
		("BAND_BACK_ALL", false, true),
	] {
		let (actions, v) = solve(graph, [lo, hi], restrict, backward)?;
		let codes: String = actions
			.into_iter()
			.map(|a| char::from(b'0' + a as u8))
			.collect();
		println!("{name} {:.17e} {:.17e} {codes}", v[0], v[1]);
	}
	Ok(())
}

#[cfg(test)]
#[path = "fee_band_tests.rs"]
mod tests;
