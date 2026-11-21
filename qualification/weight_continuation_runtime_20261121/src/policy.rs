// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded complete-DAG law, state-transition and Bellman validation before execution.

use crate::source::{SourceReceipt, VerifiedSource, LAW_TOLERANCE, PLANNING_SHA256, TASK_SHA256};
use crate::task::{self, Completion, CompletionKind, Public, State, ACTIONS};
use anyhow::{anyhow, bail, Result};
use hepta_semantic_source_adapter_study::{
	digest, unique_json, validate_sha256, SourcePin, MAX_JSON_BYTES,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bindings {
	pub compressed_sha256: String,
	pub decoded_sha256: String,
	pub task_code_sha256: String,
	pub planning_code_sha256: String,
	pub compiler_code_sha256: String,
	pub public_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
	pub probability: f64,
	pub target: usize,
	pub fee: f64,
	pub completion: Completion,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capsule {
	pub schema: String,
	pub bindings: Bindings,
	pub public: Public,
	pub public_key: String,
	pub initial: usize,
	pub states: Vec<State>,
	pub state_keys: Vec<String>,
	pub legal_masks: Vec<[bool; ACTIONS]>,
	pub posterior: Vec<f64>,
	pub edges: Vec<[Vec<Edge>; ACTIONS]>,
	pub q_values: Vec<[f64; ACTIONS]>,
	pub actions: Vec<usize>,
	pub order: Vec<usize>,
	pub policy_reachable: Vec<usize>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
	pub max_states: usize,
	pub max_edges: usize,
	pub max_matrix_products: usize,
	pub max_artifact_bytes: usize,
}

impl Default for Limits {
	fn default() -> Self {
		Self {
			max_states: 4096,
			max_edges: 36_864,
			max_matrix_products: 100_000,
			max_artifact_bytes: MAX_JSON_BYTES,
		}
	}
}

#[derive(Clone, Debug, Serialize)]
pub struct VerificationReceipt {
	pub schema: String,
	pub capsule_sha256: String,
	pub compiler_code_sha256: String,
	pub source: SourceReceipt,
	pub states: usize,
	pub edges: usize,
	pub policy_states: usize,
	pub matrix_products: usize,
	pub posterior_max_abs_error: f64,
	pub transition_probability_max_abs_error: f64,
	pub probability_sum_max_abs_error: f64,
	pub bellman_max_abs_error: f64,
	pub bellman_witnesses_bitwise_equal: bool,
	pub independently_derived_q_max_abs_error: f64,
	pub independently_derived_action_differences: usize,
	pub independently_derived_max_action_regret: f64,
	pub actions_exact: bool,
	pub state_transitions_exact: bool,
	pub law_tolerance: f64,
	pub initial_value: f64,
	pub raw_parameter_ctmc_regenerated: bool,
	pub external_owner_attested: bool,
	pub production_eligible: bool,
}

pub struct VerifiedPolicy {
	pub(crate) capsule: Capsule,
	pub(crate) reachable: BTreeSet<usize>,
	pub(crate) state_index: BTreeMap<Vec<u8>, usize>,
	pub(crate) bytes: Vec<u8>,
	receipt: VerificationReceipt,
}

impl VerifiedPolicy {
	pub fn receipt(&self) -> &VerificationReceipt {
		&self.receipt
	}
	pub fn bytes(&self) -> &[u8] {
		&self.bytes
	}
	pub fn public(&self) -> &Public {
		&self.capsule.public
	}
	pub fn selected_action(&self, state: &State) -> Result<usize> {
		let index = self.lookup(state)?;
		Ok(self.capsule.actions[index])
	}
	pub(crate) fn lookup(&self, state: &State) -> Result<usize> {
		let index = self
			.state_index
			.get(&state_identity(state)?)
			.copied()
			.ok_or_else(|| anyhow!("unknown complete state"))?;
		if !self.reachable.contains(&index) {
			bail!("state is outside the selected policy closure");
		}
		Ok(index)
	}
	pub fn public_matches(&self, public: &Public) -> Result<()> {
		if public != &self.capsule.public {
			bail!("runtime schedule differs from compiled capsule");
		}
		Ok(())
	}
}

pub(crate) fn state_identity(state: &State) -> Result<Vec<u8>> {
	// All fields, including charges and pending metadata, participate. These local
	// bytes are not advertised as Python's canonical JSON representation.
	Ok(serde_json::to_vec(state)?)
}

fn same_bits(a: f64, b: f64) -> bool {
	a.to_bits() == b.to_bits()
}

pub fn verify_policy(
	source: &VerifiedSource,
	bytes: &[u8],
	reviewed_capsule_pin: &SourcePin,
	compiler_bytes: &[u8],
	reviewed_compiler_pin: &SourcePin,
	limits: Limits,
) -> Result<VerifiedPolicy> {
	let maximum = Limits::default();
	if limits.max_states == 0
		|| limits.max_states > maximum.max_states
		|| limits.max_edges > maximum.max_edges
		|| limits.max_matrix_products > maximum.max_matrix_products
		|| limits.max_artifact_bytes == 0
		|| limits.max_artifact_bytes > maximum.max_artifact_bytes
	{
		bail!("caller cannot expand the reviewed verification budget");
	}
	reviewed_capsule_pin.verify(bytes, limits.max_artifact_bytes)?;
	reviewed_compiler_pin.verify(compiler_bytes, MAX_JSON_BYTES)?;
	let capsule: Capsule = serde_json::from_value(unique_json(bytes)?)?;
	if capsule.schema != "hepta-own-law-policy-capsule-v1" {
		bail!("unknown graph schema");
	}
	for hash in [
		&capsule.bindings.compressed_sha256,
		&capsule.bindings.decoded_sha256,
		&capsule.bindings.task_code_sha256,
		&capsule.bindings.planning_code_sha256,
		&capsule.bindings.compiler_code_sha256,
		&capsule.bindings.public_sha256,
	] {
		validate_sha256(hash)?;
	}
	if capsule.bindings.compressed_sha256 != source.receipt.compressed_sha256
		|| capsule.bindings.decoded_sha256 != source.receipt.decoded_sha256
		|| capsule.bindings.task_code_sha256 != TASK_SHA256
		|| capsule.bindings.planning_code_sha256 != PLANNING_SHA256
		|| capsule.bindings.compiler_code_sha256 != reviewed_compiler_pin.sha256
		|| digest(capsule.public_key.as_bytes()) != capsule.bindings.public_sha256
	{
		bail!("compiled policy source/task/law bindings differ from reviewed inputs");
	}
	let public_from_key: Public =
		serde_json::from_value(unique_json(capsule.public_key.as_bytes())?)?;
	if public_from_key != capsule.public {
		bail!("public key differs from complete public schedule");
	}
	capsule.public.validate()?;
	source.law.validate_schedule(&capsule.public)?;
	let n = capsule.states.len();
	if n == 0
		|| n > limits.max_states
		|| capsule.initial >= n
		|| capsule.state_keys.len() != n
		|| capsule.legal_masks.len() != n
		|| capsule.posterior.len() != n
		|| capsule.edges.len() != n
		|| capsule.q_values.len() != n
		|| capsule.actions.len() != n
		|| capsule.order.len() != n
	{
		bail!("graph dimensions or state budget differ");
	}
	let order: Vec<_> = (0..n).collect();
	let mut expected_order = order.clone();
	expected_order.sort_by_key(|index| capsule.states[*index].tick);
	if capsule.order != expected_order
		|| state_identity(&capsule.states[capsule.initial])?
			!= state_identity(&task::initial(&capsule.public)?)?
	{
		bail!("initial state or stable topological order differs");
	}
	let mut state_index = BTreeMap::new();
	let mut edges = 0usize;
	let mut matrix_products = 0usize;
	let mut posterior_error: f64 = 0.0;
	let mut probability_error: f64 = 0.0;
	let mut sum_error: f64 = 0.0;
	let mut native_posterior = vec![0.0; n];
	let mut native_probabilities: Vec<[Vec<f64>; ACTIONS]> = (0..n)
		.map(|_| std::array::from_fn(|_| Vec::new()))
		.collect();
	for (index, state) in capsule.states.iter().enumerate() {
		task::validate_state(&capsule.public, state)?;
		if state.terminal {
			bail!("DAG witnesses must be nonterminal decision states");
		}
		let keyed: State =
			serde_json::from_value(unique_json(capsule.state_keys[index].as_bytes())?)?;
		if state_identity(&keyed)? != state_identity(state)? {
			bail!("state key omits or changes complete state");
		}
		if state_index.insert(state_identity(state)?, index).is_some() {
			bail!("duplicate complete state");
		}
		if capsule.legal_masks[index] != task::legal(&capsule.public, state) {
			bail!("forged action mask");
		}
		let p = capsule.posterior[index];
		if !p.is_finite() || !(0.0..=1.0).contains(&p) {
			bail!("invalid endpoint posterior");
		}
		matrix_products = matrix_products
			.checked_add(6)
			.ok_or_else(|| anyhow!("verification counter overflow"))?;
		if matrix_products > limits.max_matrix_products {
			bail!("law verification budget exhausted");
		}
		native_posterior[index] = source.law.posterior(&capsule.public, state)?;
		let error = (p - native_posterior[index]).abs();
		posterior_error = posterior_error.max(error);
		if error > LAW_TOLERANCE {
			bail!("posterior not derived from original stored law");
		}
		for (action, native_row) in native_probabilities[index].iter_mut().enumerate() {
			let row = &capsule.edges[index][action];
			if !capsule.legal_masks[index][action] || [0, 4, 5].contains(&action) {
				if !row.is_empty() {
					bail!("terminal or illegal action has outgoing edges");
				}
				continue;
			}
			let completions = task::completions(&capsule.public, state, action)?;
			if row.len() != completions.len() || row.len() > 3 {
				bail!("missing, duplicated or reordered structural outcomes");
			}
			edges = edges
				.checked_add(row.len())
				.ok_or_else(|| anyhow!("edge counter overflow"))?;
			if edges > limits.max_edges {
				bail!("edge verification budget exhausted");
			}
			let mut total = 0.0;
			for (edge, completion) in row.iter().zip(completions) {
				if edge.target >= n
					|| edge.completion != completion
					|| !edge.probability.is_finite()
					|| !(0.0..=1.0).contains(&edge.probability)
					|| !edge.fee.is_finite()
					|| edge.fee < 0.0
				{
					bail!("invalid graph edge domain or ordered observation");
				}
				let after = task::successor(&capsule.public, state, action, completion)?;
				if state_identity(&after)? != state_identity(&capsule.states[edge.target])?
					|| !same_bits(edge.fee, after.charges - state.charges)
				{
					bail!("edge is not the complete source-task transition");
				}
				if completion.kind == CompletionKind::Observation {
					matrix_products = matrix_products
						.checked_add(state.tick + 1)
						.ok_or_else(|| anyhow!("matrix counter overflow"))?;
					if matrix_products > limits.max_matrix_products {
						bail!("law verification budget exhausted");
					}
				}
				let probability = source.law.probability(&capsule.public, state, completion)?;
				native_row.push(probability);
				let error = (probability - edge.probability).abs();
				probability_error = probability_error.max(error);
				if error > LAW_TOLERANCE {
					bail!("edge probability not derived from original stored law");
				}
				total += edge.probability;
			}
			sum_error = sum_error.max((total - 1.0).abs());
			if (total - 1.0).abs() > LAW_TOLERANCE {
				bail!("edge probability mass is not normalized");
			}
		}
	}
	let mut all_reachable = BTreeSet::new();
	let mut pending = vec![capsule.initial];
	while let Some(index) = pending.pop() {
		if all_reachable.insert(index) {
			for edge in capsule.edges[index].iter().flatten() {
				pending.push(edge.target);
			}
		}
	}
	if all_reachable.len() != n {
		bail!("unreachable additions are not part of the full legal DAG");
	}
	let mut values = vec![0.0; n];
	let mut actions = vec![0; n];
	let mut bellman_error: f64 = 0.0;
	let mut native_values = vec![0.0; n];
	let mut native_q_error: f64 = 0.0;
	let mut native_action_differences = 0;
	let mut native_action_regret: f64 = 0.0;
	for &index in capsule.order.iter().rev() {
		let p = capsule.posterior[index];
		let mut q = [0.0, 0.0, 0.0, 0.0, 1.0 - 2.0 * p, 2.0 * p - 1.0];
		for (action, score) in q.iter_mut().enumerate().take(4).skip(1) {
			if capsule.legal_masks[index][action] {
				let mut total = 0.0;
				for edge in &capsule.edges[index][action] {
					if edge.probability != 0.0 {
						total += edge.probability * (values[edge.target] - edge.fee);
					}
				}
				*score = total;
			}
		}
		let mut chosen = 0;
		for action in 0..ACTIONS {
			let witness = capsule.q_values[index][action];
			if !witness.is_finite() {
				bail!("nonfinite Q witness");
			}
			bellman_error = bellman_error.max((q[action] - witness).abs());
			if !same_bits(q[action], witness) {
				bail!("Q witness differs from ordered F64 Bellman arithmetic");
			}
			if capsule.legal_masks[index][action] && q[action] > q[chosen] {
				chosen = action;
			}
		}
		if chosen != capsule.actions[index] {
			bail!("policy choice differs from lowest-index exact argmax");
		}
		actions[index] = chosen;
		values[index] = q[chosen];
		let native_p = native_posterior[index];
		let mut native_q = [
			0.0,
			0.0,
			0.0,
			0.0,
			1.0 - 2.0 * native_p,
			2.0 * native_p - 1.0,
		];
		for (action, score) in native_q.iter_mut().enumerate().take(4).skip(1) {
			for (edge, probability) in capsule.edges[index][action]
				.iter()
				.zip(&native_probabilities[index][action])
			{
				if *probability != 0.0 {
					*score += probability * (native_values[edge.target] - edge.fee);
				}
			}
		}
		let mut native_chosen = 0;
		for action in 0..ACTIONS {
			native_q_error = native_q_error.max((native_q[action] - q[action]).abs());
			if capsule.legal_masks[index][action] && native_q[action] > native_q[native_chosen] {
				native_chosen = action;
			}
		}
		native_action_differences += usize::from(chosen != native_chosen);
		native_action_regret = native_action_regret.max(native_q[native_chosen] - native_q[chosen]);
		native_values[index] = native_q[native_chosen];
	}
	let mut reachable = BTreeSet::new();
	let mut pending = vec![capsule.initial];
	while let Some(index) = pending.pop() {
		if reachable.insert(index) {
			for edge in &capsule.edges[index][actions[index]] {
				pending.push(edge.target);
			}
		}
	}
	if capsule.policy_reachable != reachable.iter().copied().collect::<Vec<_>>() {
		bail!("policy pruning omits or adds structural observation paths");
	}
	let receipt = VerificationReceipt {
		schema: "hepta.native-continuation-verification.v1".into(),
		capsule_sha256: digest(bytes),
		compiler_code_sha256: reviewed_compiler_pin.sha256.clone(),
		source: source.receipt.clone(),
		states: n,
		edges,
		policy_states: reachable.len(),
		matrix_products,
		posterior_max_abs_error: posterior_error,
		transition_probability_max_abs_error: probability_error,
		probability_sum_max_abs_error: sum_error,
		bellman_max_abs_error: bellman_error,
		bellman_witnesses_bitwise_equal: true,
		independently_derived_q_max_abs_error: native_q_error,
		independently_derived_action_differences: native_action_differences,
		independently_derived_max_action_regret: native_action_regret,
		actions_exact: true,
		state_transitions_exact: true,
		law_tolerance: LAW_TOLERANCE,
		initial_value: values[capsule.initial],
		raw_parameter_ctmc_regenerated: false,
		external_owner_attested: false,
		production_eligible: false,
	};
	Ok(VerifiedPolicy {
		capsule,
		reachable,
		state_index,
		bytes: bytes.to_vec(),
		receipt,
	})
}
