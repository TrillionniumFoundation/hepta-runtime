// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact Bellman recursion for a declared finite law, including verification and stopping.

use super::digest;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
	Probe,
	AnalyticEdit,
	LocalTrain,
	Verify,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
	Unmodified,
	UnverifiedCandidate,
	VerifiedCandidate,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
	pub compute: u32,
	pub feedback: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
	pub probability: f64,
	pub next_state: usize,
	pub observation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
	pub id: String,
	pub kind: ActionKind,
	pub resource_cost: Budget,
	pub utility_cost: f64,
	pub outcomes: Vec<Outcome>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionState {
	pub id: String,
	pub phase: Phase,
	pub verified_use_gain: f64,
	pub actions: Vec<Action>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FiniteLaw {
	pub schema: String,
	pub cost_unit: String,
	pub information_scope: String,
	pub initial_state: usize,
	pub states: Vec<DecisionState>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Choice {
	Stop,
	Retain,
	Execute { action: usize, id: String },
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyPoint {
	pub state: usize,
	pub budget: Budget,
	pub value: f64,
	pub choice: Choice,
}

#[derive(Clone, Debug, Serialize)]
pub struct Plan {
	pub schema: String,
	pub law_sha256: String,
	pub budget: Budget,
	pub expected_net_gain: f64,
	pub first_choice: Choice,
	pub reachable_policy: Vec<PolicyPoint>,
	pub bellman_cells: usize,
	pub scope: String,
}

impl FiniteLaw {
	pub fn validate(&self) -> Result<()> {
		if self.schema != "hepta.finite-edit-law.v1"
			|| self.cost_unit.is_empty()
			|| self.cost_unit.len() > 256
			|| self.information_scope.is_empty()
			|| self.states.is_empty()
			|| self.states.len() > 256
			|| self.initial_state >= self.states.len()
		{
			bail!("bounded explicitly costed finite law required");
		}
		let mut state_ids = BTreeSet::new();
		for state in &self.states {
			if state.id.is_empty()
				|| state.id.len() > 128
				|| !state_ids.insert(&state.id)
				|| !state.verified_use_gain.is_finite()
				|| state.verified_use_gain.abs() > 1e6
				|| (state.phase != Phase::VerifiedCandidate && state.verified_use_gain != 0.)
				|| state.actions.len() > 16
			{
				bail!("state identity, verification phase or finite gain invalid");
			}
			let mut action_ids = BTreeSet::new();
			for action in &state.actions {
				if action.id.is_empty()
					|| action.id.len() > 128
					|| !action_ids.insert(&action.id)
					|| action.resource_cost.compute == 0
					|| action.resource_cost.compute > 128
					|| action.resource_cost.feedback > 16
					|| !action.utility_cost.is_finite()
					|| action.utility_cost < 0.
					|| action.utility_cost > 1e6
					|| action.outcomes.is_empty()
					|| action.outcomes.len() > 64
				{
					bail!("bounded positive resource decrement and finite cost required");
				}
				let mut sum = 0.;
				let mut observations = BTreeSet::new();
				for outcome in &action.outcomes {
					if !outcome.probability.is_finite()
						|| outcome.probability < 0.
						|| outcome.probability > 1.
						|| outcome.next_state >= self.states.len()
						|| outcome.observation.is_empty()
						|| outcome.observation.len() > 128
						|| !observations.insert(&outcome.observation)
					{
						bail!("finite normalized observations and valid successor required");
					}
					let destination = self.states[outcome.next_state].phase;
					let legal = match action.kind {
						ActionKind::Probe => {
							state.phase == Phase::Unmodified && destination == Phase::Unmodified
						}
						ActionKind::AnalyticEdit | ActionKind::LocalTrain => {
							state.phase == Phase::Unmodified
								&& destination == Phase::UnverifiedCandidate
						}
						ActionKind::Verify => {
							state.phase == Phase::UnverifiedCandidate
								&& destination == Phase::VerifiedCandidate
						}
					};
					if !legal {
						bail!("action bypasses semantic edit/verification phase");
					}
					sum += outcome.probability;
				}
				if (sum - 1.).abs() > 1e-12 {
					bail!("outcome probabilities do not sum to one");
				}
			}
		}
		Ok(())
	}
}

pub fn solve(
	law: &FiniteLaw,
	budget: Budget,
	allowed: Option<&BTreeSet<ActionKind>>,
) -> Result<Plan> {
	law.validate()?;
	if budget.compute > 128 || budget.feedback > 16 {
		bail!("planner budget bound exceeded");
	}
	let n = law.states.len();
	let feedback = budget.feedback as usize + 1;
	let index = |s: usize, c: u32, f: u32| (c as usize * feedback + f as usize) * n + s;
	let cells = n * (budget.compute as usize + 1) * feedback;
	let mut values = vec![0_f64; cells];
	let mut selected = vec![None; cells];
	for c in 0..=budget.compute {
		for f in 0..=budget.feedback {
			for (s, state) in law.states.iter().enumerate() {
				let at = index(s, c, f);
				let mut best = state.verified_use_gain.max(0.);
				for (a, action) in state.actions.iter().enumerate() {
					if allowed.is_some_and(|set| !set.contains(&action.kind))
						|| action.resource_cost.compute > c
						|| action.resource_cost.feedback > f
					{
						continue;
					}
					let next_c = c - action.resource_cost.compute;
					let next_f = f - action.resource_cost.feedback;
					let value = -action.utility_cost
						+ action
							.outcomes
							.iter()
							.map(|o| o.probability * values[index(o.next_state, next_c, next_f)])
							.sum::<f64>();
					if !value.is_finite() {
						bail!("Bellman arithmetic overflow");
					}
					// Deterministic ties keep the incumbent or the earlier declared action.
					if value > best + 1e-12 {
						best = value;
						selected[at] = Some(a);
					}
				}
				values[at] = best;
			}
		}
	}
	let choice = |s: usize, c: u32, f: u32| match selected[index(s, c, f)] {
		Some(a) => Choice::Execute {
			action: a,
			id: law.states[s].actions[a].id.clone(),
		},
		None if law.states[s].verified_use_gain > 0. => Choice::Retain,
		None => Choice::Stop,
	};
	let first_choice = choice(law.initial_state, budget.compute, budget.feedback);
	let mut queue = VecDeque::from([(law.initial_state, budget.compute, budget.feedback)]);
	let mut visited = BTreeSet::new();
	let mut policy = Vec::new();
	while let Some((s, c, f)) = queue.pop_front() {
		if !visited.insert((s, c, f)) {
			continue;
		}
		if visited.len() > 8192 {
			bail!("reachable policy output bound exceeded");
		}
		policy.push(PolicyPoint {
			state: s,
			budget: Budget {
				compute: c,
				feedback: f,
			},
			value: values[index(s, c, f)],
			choice: choice(s, c, f),
		});
		if let Some(a) = selected[index(s, c, f)] {
			let action = &law.states[s].actions[a];
			for outcome in &action.outcomes {
				if outcome.probability > 0. {
					queue.push_back((
						outcome.next_state,
						c - action.resource_cost.compute,
						f - action.resource_cost.feedback,
					));
				}
			}
		}
	}
	Ok(Plan {
		schema: "hepta.finite-edit-plan.v1".into(),
		law_sha256: digest(&serde_json::to_vec(law)?),
		budget,
		expected_net_gain: values[index(law.initial_state, budget.compute, budget.feedback)],
		first_choice,
		reachable_policy: policy,
		bellman_cells: cells,
		scope: "exact_finite_declared_law_expected_utility_not_unknown_environment_optimality"
			.into(),
	})
}
