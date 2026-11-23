// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Plan one common additive shift for the three continuation readout biases.
//! Search representable midpoints of open score cells plus the exact incumbent.
use super::{fee_band, token, Graph, Outcome, State, ACTIONS, TOLERANCE};

const MARKER: &str = "HEPTA_Q_SCORES_V1";
const TIE_BAND: f64 = 1e-12;
const MAX_STATE_CELLS: usize = 50_000_000;

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

fn solve(input: &str, fees: [f64; 2], radius: f64) -> Outcome<Plan> {
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
	if graph.states.len().saturating_mul(midpoints.len()) > MAX_STATE_CELLS {
		return Err("state by open-cell evaluation count exceeds planner budget".into());
	}
	let incumbent: Vec<_> = graph.states.iter().map(|s| s.original).collect();
	let baseline = fee_band::evaluate(&graph, &incumbent, fees)[graph.initial];
	let policy = |shift| switches.iter().map(|s| s.action(shift)).collect::<Vec<_>>();
	let mut candidates = Vec::with_capacity(midpoints.len());
	let mut best = 0.0_f64;
	for &shift in &midpoints {
		let values = fee_band::evaluate(&graph, &policy(shift), fees)[graph.initial];
		let gains = [values[0] - baseline[0], values[1] - baseline[1]];
		if !gains.iter().all(|v| v.is_finite()) {
			return Err("nonfinite root gain".into());
		}
		let gain = gains[0].min(gains[1]);
		best = best.max(gain);
		candidates.push((gain, shift, gains));
	}
	// Compare against the final maximum before breaking ties, so tie chains cannot drift.
	if let Some((_, shift, gains)) = candidates
		.into_iter()
		.filter(|(gain, _, _)| *gain >= best - TIE_BAND && *gain > TOLERANCE)
		.min_by(|a, b| a.1.abs().total_cmp(&b.1.abs()).then(a.1.total_cmp(&b.1)))
	{
		return Ok(Plan {
			shift,
			gains,
			cells: midpoints.len(),
			actions: policy(shift),
		});
	}
	Ok(Plan {
		shift: 0.,
		gains: [0.; 2],
		cells: midpoints.len(),
		actions: incumbent,
	})
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
