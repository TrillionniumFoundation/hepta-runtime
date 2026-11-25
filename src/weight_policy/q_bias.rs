// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Plan one common additive shift for the three continuation readout biases.
//! Search frozen score cells; retain interior fallbacks for actual reopened evaluation.
use super::{fee_band, token, Graph, Outcome, State, ACTIONS, TOLERANCE};

const MARKER: &str = "HEPTA_Q_SCORES_V1";
const TIE_BAND: f64 = 1e-12;
const MAX_STATE_CELLS: usize = 50_000_000;
const MAX_CANDIDATES: usize = 64;
const REOPENED_MARKER: &str = "HEPTA_Q_REOPENED_V1";

enum Switch {
	Fixed(usize),
	At { stop: usize, go: usize, margin: f64 },
}

impl Switch {
	fn from_scores(state: &State, scores: [f64; ACTIONS]) -> Outcome<Self> {
		if !scores.iter().all(|s| s.is_finite()) {
			return Err("every frozen score must be finite".into());
		}
		let best = |actions: &[usize]| {
			actions
				.iter()
				.copied()
				.filter(|&a| state.legal(a))
				.reduce(|a, b| if scores[b] > scores[a] { b } else { a })
		};
		if best(&[0, 1, 2, 3, 4, 5]) != Some(state.original) {
			return Err("frozen scores disagree with incumbent action".into());
		}
		match (best(&[0, 4, 5]), best(&[1, 2, 3])) {
			(Some(stop), Some(go)) => {
				let margin = scores[stop] - scores[go];
				if !margin.is_finite() {
					return Err("score margin exceeds numerical range".into());
				}
				Ok(Self::At { stop, go, margin })
			}
			(Some(action), None) | (None, Some(action)) => Ok(Self::Fixed(action)),
			(None, None) => Err("state has no legal action".into()),
		}
	}

	fn action(&self, shift: f64) -> usize {
		match *self {
			Self::Fixed(action) => action,
			Self::At { stop, go, margin } => {
				if shift > margin {
					go
				} else if shift < margin {
					stop
				} else {
					stop.min(go)
				}
			}
		}
	}
}

struct Plan {
	shift: f64,
	gains: [f64; 2],
	cells: usize,
	actions: Vec<usize>,
}

#[derive(Clone)]
struct Trial {
	shift: f64,
	gains: [f64; 2],
	interior: bool,
}

struct Search {
	graph: Graph,
	switches: Vec<Switch>,
	trials: Vec<Trial>,
	cells: usize,
}

fn best_trial(trials: &[Trial]) -> Option<usize> {
	let best = trials
		.iter()
		.map(|t| t.gains[0].min(t.gains[1]))
		.fold(0.0_f64, f64::max);
	trials
		.iter()
		.enumerate()
		.filter(|(_, t)| {
			let gain = t.gains[0].min(t.gains[1]);
			gain >= best - TIE_BAND && gain > TOLERANCE
		})
		.min_by(|(_, a), (_, b)| {
			a.shift
				.abs()
				.total_cmp(&b.shift.abs())
				.then(a.shift.total_cmp(&b.shift))
		})
		.map(|(i, _)| i)
}

fn search(input: &str, fees: [f64; 2], radius: f64) -> Outcome<Search> {
	if !radius.is_finite() || radius <= 0. || radius > f64::MAX / 2. {
		return Err("expected a positive finite scalar radius within numerical range".into());
	}
	let (graph_text, rows) = input.split_once(MARKER).ok_or("missing Q score table")?;
	if !graph_text.ends_with(char::is_whitespace) || !rows.starts_with(char::is_whitespace) {
		return Err("expected a separate Q score table marker".into());
	}
	let graph = Graph::parse(graph_text)?;
	fee_band::validate(&graph, fees)?;
	let mut fields = rows.split_whitespace();
	let mut switches = Vec::with_capacity(graph.states.len());
	let mut limits = vec![-radius, radius];
	for state in &graph.states {
		let mut scores = [0.; ACTIONS];
		for entry in &mut scores {
			*entry = token(&mut fields, "Q score")?;
		}
		let switch = Switch::from_scores(state, scores)?;
		match switch {
			Switch::At { margin, .. } if margin > -radius && margin < radius => limits.push(margin),
			_ => (),
		}
		switches.push(switch);
	}
	if fields.next().is_some() {
		return Err("extra Q scores".into());
	}
	limits.sort_unstable_by(f64::total_cmp);
	limits.dedup_by(|a, b| *a == *b);
	let midpoints: Vec<_> = limits
		.windows(2)
		.filter_map(|w| {
			let mid = (w[0] + w[1]) / 2.;
			(w[0] < mid && mid < w[1]).then_some(mid)
		})
		.collect();
	// A tied legal argmax can differ from both neighboring policies: stop action 0
	// wins a tie, while continuation actions 1..=3 beat stop actions 4 and 5.
	// The radius is closed, so its two endpoints are admissible as well.
	let evaluated_shifts = midpoints.len().saturating_add(limits.len());
	if graph.states.len().saturating_mul(evaluated_shifts) > MAX_STATE_CELLS {
		return Err("state by evaluated-shift count exceeds planner budget".into());
	}
	let incumbent: Vec<_> = graph.states.iter().map(|s| s.original).collect();
	let baseline = fee_band::evaluate(&graph, &incumbent, fees)[graph.initial];
	let policy = |shift| switches.iter().map(|s| s.action(shift)).collect::<Vec<_>>();
	let mut candidates = Vec::with_capacity(evaluated_shifts);
	for (index, &shift) in midpoints.iter().chain(&limits).enumerate() {
		let values = fee_band::evaluate(&graph, &policy(shift), fees)[graph.initial];
		let gains = [values[0] - baseline[0], values[1] - baseline[1]];
		if !gains.iter().all(|v| v.is_finite()) {
			return Err("nonfinite root gain".into());
		}
		candidates.push(Trial {
			shift,
			gains,
			interior: index < midpoints.len(),
		});
	}
	Ok(Search {
		graph,
		switches,
		trials: candidates,
		cells: midpoints.len(),
	})
}

impl Search {
	fn actions(&self, shift: f64) -> Vec<usize> {
		self.switches.iter().map(|s| s.action(shift)).collect()
	}

	fn candidates(&self, limit: usize) -> Outcome<Vec<Trial>> {
		if !(2..=MAX_CANDIDATES).contains(&limit) {
			return Err("candidate limit must be an integer in 2..=64".into());
		}
		let mut remaining = self.trials.clone();
		let mut selected = Vec::new();
		if let Some(i) = best_trial(&remaining) {
			selected.push(remaining.remove(i));
		}
		// A boundary and an interior can predict the same policy but round to
		// different policies after bias serialization and the full forward pass.
		// Reserve the old open-cell winner before ranking the remaining shifts.
		let interior: Vec<_> = self.trials.iter().filter(|t| t.interior).cloned().collect();
		if let Some(i) = best_trial(&interior) {
			if let Some(j) = remaining.iter().position(|t| t.shift == interior[i].shift) {
				selected.push(remaining.remove(j));
			}
		}
		while selected.len() < limit {
			let Some(i) = best_trial(&remaining) else {
				break;
			};
			selected.push(remaining.remove(i));
		}
		Ok(selected)
	}
}

fn solve(input: &str, fees: [f64; 2], radius: f64) -> Outcome<Plan> {
	let search = search(input, fees, radius)?;
	// Compare against the final maximum before breaking ties, so tie chains cannot drift.
	if let Some(i) = best_trial(&search.trials) {
		let trial = &search.trials[i];
		return Ok(Plan {
			shift: trial.shift,
			gains: trial.gains,
			cells: search.cells,
			actions: search.actions(trial.shift),
		});
	}
	Ok(Plan {
		shift: 0.,
		gains: [0.; 2],
		cells: search.cells,
		actions: search.graph.states.iter().map(|s| s.original).collect(),
	})
}

fn codes(actions: &[usize]) -> String {
	actions
		.iter()
		.map(|&a| char::from(b'0' + a as u8))
		.collect()
}

pub(super) fn run_candidates(input: &str, parameters: &[f64], reopened: bool) -> Outcome<()> {
	let [low, high, radius, limit] = *parameters else {
		return Err("expected MIN MAX RADIUS LIMIT".into());
	};
	if !limit.is_finite() || limit.fract() != 0. || !(2.0..=64.0).contains(&limit) {
		return Err("candidate limit must be an integer in 2..=64".into());
	}
	let (plan_text, rows) = if reopened {
		let (plan, rows) = input
			.split_once(REOPENED_MARKER)
			.ok_or("missing reopened table")?;
		if !plan.ends_with(char::is_whitespace) || !rows.starts_with(char::is_whitespace) {
			return Err("expected a separate reopened table marker".into());
		}
		(plan, Some(rows))
	} else {
		(input, None)
	};
	let fees = [low, high];
	let search = search(plan_text, fees, radius)?;
	let candidates = search.candidates(limit as usize)?;
	if let Some(rows) = rows {
		return select_reopened(&search, &candidates, fees, rows);
	}
	println!(
		"Q_BIAS_CANDIDATES_V1 {} {} {}",
		candidates.len(),
		search.cells,
		search.trials.len()
	);
	for (i, trial) in candidates.iter().enumerate() {
		let kind = if trial.interior {
			"INTERIOR"
		} else {
			"BOUNDARY"
		};
		println!(
			"Q_BIAS_CANDIDATE {} {kind} {:.17e} {:.17e} {:.17e} {}",
			i + 1,
			trial.shift,
			trial.gains[0],
			trial.gains[1],
			codes(&search.actions(trial.shift))
		);
	}
	Ok(())
}

/// The caller owns materialization, reopening and source receipts. This selector
/// requires one result (or explicit FAILED) for every regenerated plan member.
fn select_reopened(
	search: &Search,
	candidates: &[Trial],
	fees: [f64; 2],
	rows: &str,
) -> Outcome<()> {
	let mut fields = rows.split_whitespace();
	let count: usize = token(&mut fields, "reopened candidate count")?;
	if count != candidates.len() {
		return Err("reopened candidate count differs from regenerated plan".into());
	}
	let total_shifts = search.trials.len().saturating_add(candidates.len());
	if search.graph.states.len().saturating_mul(total_shifts) > MAX_STATE_CELLS {
		return Err("combined planner and reopened evaluation exceeds planner budget".into());
	}
	let source: Vec<_> = search.graph.states.iter().map(|s| s.original).collect();
	let baseline = fee_band::evaluate(&search.graph, &source, fees)[search.graph.initial];
	let mut actual_trials = Vec::new();
	let mut actual_policies = Vec::new();
	for (i, trial) in candidates.iter().enumerate() {
		let shift: f64 = token(&mut fields, "reopened shift")?;
		if shift.to_bits() != trial.shift.to_bits() {
			return Err("reopened shift differs from regenerated plan".into());
		}
		let text = fields.next().ok_or("missing reopened actions or FAILED")?;
		if text == "FAILED" {
			continue;
		}
		if text.len() != source.len() {
			return Err("reopened action count differs".into());
		}
		let mut actions = Vec::with_capacity(source.len());
		for (c, state) in text.bytes().zip(&search.graph.states) {
			let action = c.wrapping_sub(b'0') as usize;
			if !state.legal(action) {
				return Err("illegal reopened action".into());
			}
			actions.push(action);
		}
		let values = fee_band::evaluate(&search.graph, &actions, fees)[search.graph.initial];
		let gains = [values[0] - baseline[0], values[1] - baseline[1]];
		if !gains.iter().all(|v| v.is_finite()) {
			return Err("nonfinite reopened root gain".into());
		}
		actual_trials.push(Trial {
			shift,
			gains,
			interior: trial.interior,
		});
		actual_policies.push((i + 1, actions));
	}
	if fields.next().is_some() {
		return Err("extra reopened candidate fields".into());
	}
	if let Some(i) = best_trial(&actual_trials) {
		let trial = &actual_trials[i];
		let (id, actions) = &actual_policies[i];
		let mismatch = actions
			.iter()
			.zip(search.actions(trial.shift))
			.filter(|(a, b)| **a != *b)
			.count();
		println!(
			"Q_BIAS_SELECTED {id} {:.17e} {:.17e} {:.17e} {mismatch} {}",
			trial.shift,
			trial.gains[0],
			trial.gains[1],
			codes(actions)
		);
	} else {
		println!("Q_BIAS_KEEP 0 0 0 0 0 {}", codes(&source));
	}
	Ok(())
}

pub(super) fn run(input: &str, fees: [f64; 2], radius: f64) -> Outcome<()> {
	let p = solve(input, fees, radius)?;
	let actions: String = p
		.actions
		.iter()
		.map(|&a| char::from(b'0' + a as u8))
		.collect();
	println!(
		"Q_BIAS_PLAN {:.17e} {:.17e} {:.17e} {} {}",
		p.shift, p.gains[0], p.gains[1], p.cells, actions
	);
	Ok(())
}

/// Original, direct and reverse carry the incumbent, reopened and proposed actions.
pub(super) fn verify(graph: &Graph, fees: [f64; 2]) -> Outcome<()> {
	fee_band::validate(graph, fees)?;
	let source: Vec<_> = graph.states.iter().map(|s| s.original).collect();
	let actual: Vec<_> = graph.states.iter().map(|s| s.direct).collect();
	let base = fee_band::evaluate(graph, &source, fees)[graph.initial];
	let values = fee_band::evaluate(graph, &actual, fees)[graph.initial];
	let gains = [values[0] - base[0], values[1] - base[1]];
	if !gains.iter().all(|v| v.is_finite()) {
		return Err("nonfinite reopened root gain".into());
	}
	let mismatch = graph
		.states
		.iter()
		.filter(|s| s.direct != s.reverse)
		.count();
	let (status, selected) = if source == actual {
		("Q_BIAS_KEEP", &source)
	} else if gains.iter().all(|g| *g > TOLERANCE) {
		("Q_BIAS_VERIFIED", &actual)
	} else {
		("Q_BIAS_REJECT", &source)
	};
	let codes: String = selected
		.iter()
		.map(|&a| char::from(b'0' + a as u8))
		.collect();
	println!(
		"{status} {:.17e} {:.17e} {mismatch} {codes}",
		gains[0], gains[1]
	);
	Ok(())
}

#[cfg(test)]
#[path = "q_bias_tests.rs"]
mod tests;
