// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded finite-DAG Bellman planning over a caller-declared transition graph.
//!
//! This is dynamic programming, not weight editing or identification of the true
//! environment law. Child states precede their parents. Every action occupies a
//! fixed slot, illegal actions are null, and strict comparison selects the first
//! legal maximum. No discount, probability normalization, or hidden state is
//! introduced. In branch order, nonzero probability contributes exactly the F64
//! operation sequence p * ((child_value + reward) - fee), accumulated with +=.
//! The separate operations deliberately do not use mul_add or reassociate fees.
//!
//! Finite arithmetic and a repeated Bellman consistency check are engineering
//! diagnostics. They are not an outward-rounded real-arithmetic certificate, an
//! authentication of a checkpoint, or evidence of held-out task value. A graph
//! may encode separate canonical value states and caller query states without
//! revealing labels or an external reference policy to this planner.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const ACTION_NAMES: [&str; 6] = ["STOP", "WAIT", "READ", "REPAIR", "SUBMIT_0", "SUBMIT_1"];
const SEMANTICS_VERSION: &str = "finite_dag_ordered_f64_v1";
const MAX_STATES: usize = 4096;
const MAX_BRANCHES: usize = 24_576;
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_WORK: u64 = 8_000_000;
const PROBABILITY_SUM_TOLERANCE: f64 = 1e-12;
const NEAR_TIE_TOLERANCE: f64 = 2e-12;
static PLANNERS: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BellmanPlanParams {
	/// Nonempty finite DAG, at most 4096 states, with every child before its parent.
	pub states: Vec<BellmanState>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BellmanState {
	/// STOP, WAIT, READ, REPAIR, SUBMIT_0, SUBMIT_1. Null is illegal. At least one
	/// action is legal; at most two actions may continue to earlier states.
	pub actions: [Option<BellmanAction>; 6],
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BellmanAction {
	Terminal {
		/// Explicit finite terminal value, in the caller's declared value units.
		value: f64,
	},
	Continue {
		/// One to three ordered branches. Nonnegative probabilities must sum to
		/// one within 1e-12 in sequential F64 arithmetic; no renormalization.
		branches: Vec<BellmanBranch>,
	},
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BellmanBranch {
	pub probability: f64,
	/// Strictly less than the index of the state containing this action.
	pub successor: u32,
	pub reward: f64,
	/// Finite, nonnegative cost. It stays inside the branch multiplication.
	pub fee: f64,
}

#[derive(Clone, Debug, Serialize)]
struct StatePlan {
	q: [Option<f64>; 6],
	value: f64,
	action: usize,
}

#[derive(Clone, Copy, Debug)]
struct Dimensions {
	states: usize,
	legal_actions: usize,
	continuing_actions: usize,
	branches: usize,
	zero_probability_branches: usize,
	probability_sum_error: f64,
	work: u64,
}

fn finite(value: f64, operation: &str) -> Result<f64> {
	if !value.is_finite() {
		bail!("Bellman requires finite arithmetic in {operation}");
	}
	Ok(value)
}

fn deadline(end: Instant) -> Result<()> {
	if Instant::now() >= end {
		bail!("Bellman planning exceeded its 30-second compute deadline");
	}
	Ok(())
}

fn validate(params: &BellmanPlanParams, end: Instant) -> Result<Dimensions> {
	if !(1..=MAX_STATES).contains(&params.states.len()) {
		bail!("Bellman needs 1..4096 topologically ordered states");
	}
	let mut dims = Dimensions {
		states: params.states.len(),
		legal_actions: 0,
		continuing_actions: 0,
		branches: 0,
		zero_probability_branches: 0,
		probability_sum_error: 0.0,
		work: 0,
	};
	for (index, state) in params.states.iter().enumerate() {
		deadline(end)?;
		let mut legal = 0;
		let mut continuing = 0;
		for action in state.actions.iter().flatten() {
			legal += 1;
			match action {
				BellmanAction::Terminal { value } => {
					finite(*value, "terminal value")?;
				}
				BellmanAction::Continue { branches } => {
					continuing += 1;
					if !(1..=3).contains(&branches.len()) {
						bail!("Bellman continuing actions need 1..3 branches");
					}
					dims.branches += branches.len();
					if dims.branches > MAX_BRANCHES {
						bail!("Bellman exceeds its 24576-branch budget");
					}
					let mut sum = 0.0;
					for branch in branches {
						finite(branch.probability, "branch probability")?;
						finite(branch.reward, "branch reward")?;
						finite(branch.fee, "branch fee")?;
						if branch.probability < 0.0 || branch.fee < 0.0 {
							bail!("Bellman probabilities and fees must be nonnegative");
						}
						if branch.successor as usize >= index {
							bail!("Bellman successors must strictly precede their parent state");
						}
						if branch.probability == 0.0 {
							dims.zero_probability_branches += 1;
						}
						sum = finite(sum + branch.probability, "probability sum")?;
					}
					let error = (sum - 1.0).abs();
					if error > PROBABILITY_SUM_TOLERANCE {
						bail!("Bellman probabilities must sum to one within 1e-12; no normalization is performed");
					}
					dims.probability_sum_error = dims.probability_sum_error.max(error);
				}
			}
		}
		if legal == 0 || continuing > 2 {
			bail!(
				"Bellman states need at least one legal action and at most two continuing actions"
			);
		}
		dims.legal_actions += legal;
		dims.continuing_actions += continuing;
	}
	// Conservative scalar-operation admission includes input checks, the complete
	// forward pass, a second consistency pass, selection and near-tie diagnostics.
	// Serialization and hashing have their separate canonical-byte bound.
	dims.work = (dims.states as u64) * 256
		+ (dims.legal_actions as u64) * 64
		+ (dims.branches as u64) * 128;
	if dims.work > MAX_WORK {
		bail!("Bellman exceeds its scalar arithmetic work budget");
	}
	Ok(dims)
}

struct Commitment {
	hash: Sha256,
	bytes: usize,
	end: Instant,
}

impl Write for Commitment {
	fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
		if Instant::now() >= self.end {
			return Err(std::io::Error::new(
				std::io::ErrorKind::TimedOut,
				"Bellman canonical serialization exceeded its deadline",
			));
		}
		let size = self.bytes.checked_add(bytes.len()).ok_or_else(|| {
			std::io::Error::other("Bellman canonical serialization byte count overflow")
		})?;
		if size > MAX_REQUEST_BYTES {
			return Err(std::io::Error::other(
				"Bellman canonical request exceeds 8 MiB",
			));
		}
		self.hash.update(bytes);
		self.bytes = size;
		Ok(bytes.len())
	}

	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
	bytes
		.as_ref()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn action_value(action: &BellmanAction, plans: &[StatePlan]) -> Result<f64> {
	match action {
		BellmanAction::Terminal { value } => Ok(*value),
		BellmanAction::Continue { branches } => {
			let mut total = 0.0;
			for branch in branches {
				// Even a zero-probability branch was structurally validated and charged.
				if branch.probability == 0.0 {
					continue;
				}
				let child = plans.get(branch.successor as usize).ok_or_else(|| {
					anyhow!("Bellman child is not available in the solved prefix")
				})?;
				let rewarded = finite(child.value + branch.reward, "child value plus reward")?;
				let continuation = finite(rewarded - branch.fee, "branch continuation less fee")?;
				let contribution =
					finite(branch.probability * continuation, "weighted continuation")?;
				total = finite(total + contribution, "ordered action sum")?;
			}
			Ok(total)
		}
	}
}

fn choose(q: &[Option<f64>; 6]) -> Result<(usize, f64)> {
	let mut best: Option<(usize, f64)> = None;
	for (index, value) in q.iter().enumerate() {
		if let Some(value) = value {
			if best.is_none_or(|(_, previous)| *value > previous) {
				best = Some((index, *value));
			}
		}
	}
	best.ok_or_else(|| anyhow!("Bellman state has no legal action"))
}

fn solve(params: &BellmanPlanParams) -> Result<Value> {
	let started = Instant::now();
	let end = started + Duration::from_secs(30);
	let dims = validate(params, end)?;
	let mut commitment = Commitment {
		hash: Sha256::new(),
		bytes: 0,
		end,
	};
	serde_json::to_writer(&mut commitment, params)?;
	let request_bytes = commitment.bytes;
	let request_sha256 = hex(commitment.hash.finalize());
	let implementation_source_sha256 = hex(Sha256::digest(include_bytes!("weight_bellman.rs")));
	let mut identity = Sha256::new();
	identity.update(b"hepta.weight.bellman-plan.v1\0");
	identity.update(SEMANTICS_VERSION.as_bytes());
	identity.update(b"\0");
	identity.update(implementation_source_sha256.as_bytes());
	identity.update(b"\0");
	identity.update(request_sha256.as_bytes());
	let plan_id = format!("wb1_{}", hex(identity.finalize()));
	let mut plans = Vec::with_capacity(dims.states);
	let mut exact_tie_states = 0;
	let mut near_tie_states = 0;
	let mut minimum_relative_action_gap: Option<f64> = None;
	for state in &params.states {
		deadline(end)?;
		let mut q = [None; 6];
		for (index, action) in state.actions.iter().enumerate() {
			if let Some(action) = action {
				q[index] = Some(action_value(action, &plans)?);
			}
		}
		let (action, value) = choose(&q)?;
		let runner_up = q
			.iter()
			.enumerate()
			.filter(|(index, _)| *index != action)
			.filter_map(|(_, value)| *value)
			.reduce(f64::max);
		if let Some(second) = runner_up {
			let scale = 1.0_f64.max(value.abs()).max(second.abs());
			let gap = value / scale - second / scale;
			minimum_relative_action_gap =
				Some(minimum_relative_action_gap.map_or(gap, |old| old.min(gap)));
			if second == value {
				exact_tie_states += 1;
			}
			if gap <= NEAR_TIE_TOLERANCE {
				near_tie_states += 1;
			}
		}
		plans.push(StatePlan { q, value, action });
	}
	let mut maximum_consistency_residual = 0.0_f64;
	for (index, state) in params.states.iter().enumerate() {
		deadline(end)?;
		let mut recomputed = [None; 6];
		for (action, description) in state.actions.iter().enumerate() {
			if let Some(description) = description {
				let value = action_value(description, &plans[..index])?;
				recomputed[action] = Some(value);
				let previous = plans[index].q[action]
					.ok_or_else(|| anyhow!("Bellman result lost a legal action"))?;
				maximum_consistency_residual = maximum_consistency_residual
					.max(finite((value - previous).abs(), "Q consistency residual")?);
			}
		}
		let (action, value) = choose(&recomputed)?;
		if action != plans[index].action {
			bail!("Bellman repeated selection disagrees with its recorded action");
		}
		maximum_consistency_residual = maximum_consistency_residual.max(finite(
			(value - plans[index].value).abs(),
			"value consistency residual",
		)?);
	}
	deadline(end)?;
	Ok(json!({
		"schema":"hepta.weight.bellman-plan.v1", "semantics_version":SEMANTICS_VERSION,
		"method":"finite_dag_ordered_dynamic_programming_f64", "action_names":ACTION_NAMES,
		"recurrence":"in supplied branch order: total += probability * ((child_value + reward) - fee); zero probabilities skipped; first legal strict maximum",
		"plan_id":plan_id, "request_sha256":request_sha256, "request_bytes":request_bytes,
		"request_commitment_encoding":"typed canonical serde_json; not raw JSON-RPC transport bytes",
		"implementation_source_sha256":implementation_source_sha256,
		"state_count":dims.states, "legal_action_count":dims.legal_actions,
		"continuing_action_count":dims.continuing_actions, "branch_count":dims.branches,
		"zero_probability_branch_count":dims.zero_probability_branches, "states":plans,
		"probability_sum_tolerance":PROBABILITY_SUM_TOLERANCE,
		"maximum_probability_sum_error_f64":dims.probability_sum_error,
		"maximum_self_consistency_residual_f64":maximum_consistency_residual,
		"self_consistency_is_numerical_error_bound":false,
		"exact_tie_state_count":exact_tie_states, "near_tie_state_count":near_tie_states,
		"near_tie_relative_threshold":NEAR_TIE_TOLERANCE,
		"minimum_relative_action_gap_f64":minimum_relative_action_gap,
		"operation_charged_units":dims.work, "operation_budget_units":MAX_WORK,
		"canonical_request_byte_budget":MAX_REQUEST_BYTES,
		"native_operation_wall_seconds":started.elapsed().as_secs_f64(),
		"gradient_steps":0, "training_targets_used":false,
		"checkpoint_verified":false, "environment_law_verified":false,
		"real_arithmetic_optimality_certified":false, "independent_holdout_verified":false,
		"production_eligible":false,
		"scope":"bounded planning over the caller-declared finite DAG; no file access, checkpoint mutation, circuit identification, authentication of true dynamics, or end-to-end efficacy claim"
	}))
}

pub async fn plan(params: BellmanPlanParams) -> Result<String> {
	let permit = PLANNERS
		.get_or_init(|| Arc::new(Semaphore::new(2)))
		.clone()
		.try_acquire_owned()
		.map_err(|_| anyhow!("native Bellman planning capacity exhausted; no work admitted"))?;
	tokio::task::spawn_blocking(move || {
		// Cancellation of the caller does not release the permit while work remains.
		let _permit = permit;
		serde_json::to_string(&solve(&params)?).context("serializing native Bellman result")
	})
	.await
	.context("native Bellman planning worker failed")?
}

#[cfg(test)]
#[path = "weight_bellman_tests.rs"]
mod tests;
