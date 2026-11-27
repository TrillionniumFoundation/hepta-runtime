// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! A closed source-bound roundtrip policy using the original finite-law solver.
//! The probability and utility law is declared, not inferred or authenticated here.

use anyhow::{ensure, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Instant;

#[path = "../../qualification/weight_program_runtime_20261122/src/planner.rs"]
mod planner;
#[cfg(test)]
#[path = "weight_smallhcsn_ndu_tests.rs"]
mod tests;

const MAX_WEIGHTED_SUCCESSORS: u64 = 1_048_576;
const MAX_MEMORY_CELLS: u64 = 65_536;
const ARITHMETIC_SCOPE: &str =
	"conditional_finite_declared_law_existing_f64_and_1e-12_tie_tolerance";

// The same original planner file is also built by its qualification crate. Its parent
// supplies SHA256 only; the state recursion and comparison body are shared unchanged.
fn digest(bytes: &[u8]) -> String {
	crate::mcp::weight_smallhcsn::sha(bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Budget {
	/// Protocol model-phase reservation units, not measured FLOPs, money or GPU seconds.
	pub compute: u32,
	/// Protocol model-result slots, not external human feedback or free observations.
	pub feedback: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclaredLaw {
	pub information_scope: String,
	pub utility_unit: String,
	/// A commitment to the caller's calibration source; its correctness is unverified.
	pub calibration_sha256: String,
	pub verification_pass_probability: f64,
	pub use_gain_if_verified: f64,
	pub analytic_edit_utility_cost: f64,
	pub complete_verification_utility_cost: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBinding {
	pub parent_sha256: String,
	pub profile_sha256: String,
	pub raw_input_sha256: String,
	pub plan_sha256: String,
	pub candidate_sha256: String,
	pub proposal_program_sha256: String,
	pub evaluator_sha256: String,
	pub attempt_budget_sha256: String,
	pub quality_contract_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Request {
	pub law: DeclaredLaw,
	pub budget: Budget,
	/// Equality pins returned by native preparation, not a permission or evidence token.
	pub expected_execution: ExecutionBinding,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct Work {
	weighted_successor_upper_bound: u64,
	memory_cells: u64,
}

fn checked_work(states: u64, outcomes: u64, compute: u64, feedback: u64) -> Result<Work> {
	let budgets = compute
		.checked_add(1)
		.and_then(|c| feedback.checked_add(1).and_then(|f| c.checked_mul(f)))
		.context("finite planner budget product overflow")?;
	let terms = budgets
		.checked_mul(outcomes)
		.context("finite planner weighted-work overflow")?;
	let cells = budgets
		.checked_mul(states)
		.context("finite planner memory-cell overflow")?;
	ensure!(
		terms <= MAX_WEIGHTED_SUCCESSORS && cells <= MAX_MEMORY_CELLS,
		"fixed-profile planner exceeds weighted successor or memory-cell admission"
	);
	Ok(Work {
		weighted_successor_upper_bound: terms,
		memory_cells: cells,
	})
}

fn work(law: &planner::FiniteLaw, budget: Budget) -> Result<Work> {
	ensure!(
		budget.compute <= 128 && budget.feedback <= 16,
		"finite planner budget exceeds original dimensions"
	);
	law.validate()?;
	let mut outcomes = 0u64;
	for state in &law.states {
		for action in &state.actions {
			outcomes = outcomes
				.checked_add(u64::try_from(action.outcomes.len())?)
				.context("finite planner outcome count overflow")?;
		}
	}
	checked_work(
		u64::try_from(law.states.len())?,
		outcomes,
		u64::from(budget.compute),
		u64::from(budget.feedback),
	)
}

pub(in crate::mcp) fn implementation() -> String {
	digest(
		&[
			include_bytes!("weight_smallhcsn_ndu.rs").as_slice(),
			include_bytes!("../../qualification/weight_program_runtime_20261122/src/planner.rs")
				.as_slice(),
		]
		.concat(),
	)
}

pub(in crate::mcp) fn reservation() -> Value {
	json!({
		"schema":"hepta.smallhcsn.complete-roundtrip-reservation.v1",
		"compute_units":3,"feedback_units":3,"reserved_upfront":true,
		"compute_unit":"one_existing_twenty_second_model_phase_reservation_under_shared_sixty_second_window",
		"feedback_unit":"one_existing_model_result_slot",
		"analytic_edit":{"compute":1,"feedback":1,"phases":["parent"]},
		"mandatory_verify":{"compute":2,"feedback":2,"phases":["candidate","restored"]},
		"original_inverse_mandatory":true,"inverse_and_io_wall_cost_zero":false,
		"inverse_may_continue_after_model_window":true,
		"refund_on_failure_or_crash":false,"automatic_reuse_for_another_attempt":false,
		"physical_cpu_or_utility_cost_calibration_verified":false
	})
}

fn validate_binding(binding: &ExecutionBinding) -> Result<()> {
	for value in [
		&binding.parent_sha256,
		&binding.profile_sha256,
		&binding.raw_input_sha256,
		&binding.plan_sha256,
		&binding.candidate_sha256,
		&binding.proposal_program_sha256,
		&binding.evaluator_sha256,
		&binding.attempt_budget_sha256,
		&binding.quality_contract_sha256,
	] {
		ensure!(
			crate::mcp::weight_config::valid_sha256(value),
			"complete native execution mapping digest required"
		);
	}
	Ok(())
}

fn law(request: &Request, binding: &ExecutionBinding) -> Result<planner::FiniteLaw> {
	validate_binding(binding)?;
	ensure!(
		&request.expected_execution == binding,
		"declared action mapping differs from actual native candidate, evaluator or budget"
	);
	let declared = &request.law;
	ensure!(
		!declared.information_scope.is_empty()
			&& declared.information_scope.len() <= 2048
			&& !declared.utility_unit.is_empty()
			&& declared.utility_unit.len() <= 128
			&& crate::mcp::weight_config::valid_sha256(&declared.calibration_sha256)
			&& declared.verification_pass_probability.is_finite()
			&& (0.0..=1.0).contains(&declared.verification_pass_probability)
			&& declared.use_gain_if_verified.is_finite()
			&& (0.0..=1e6).contains(&declared.use_gain_if_verified),
		"bounded caller-declared finite law and calibration commitment required"
	);
	let edit_id = format!("sender40:{}", binding.candidate_sha256);
	let verify_id = format!("verify:{}", binding.evaluator_sha256);
	let states = vec![
		planner::DecisionState {
			id: "unmodified".into(),
			phase: planner::Phase::Unmodified,
			verified_use_gain: 0.0,
			actions: vec![planner::Action {
				id: edit_id,
				kind: planner::ActionKind::AnalyticEdit,
				resource_cost: planner::Budget {
					compute: 1,
					feedback: 1,
				},
				utility_cost: declared.analytic_edit_utility_cost,
				outcomes: vec![planner::Outcome {
					probability: 1.0,
					next_state: 1,
					observation: "candidate_requires_complete_verification".into(),
				}],
			}],
		},
		planner::DecisionState {
			id: "unverified_candidate".into(),
			phase: planner::Phase::UnverifiedCandidate,
			verified_use_gain: 0.0,
			actions: vec![planner::Action {
				id: verify_id,
				kind: planner::ActionKind::Verify,
				resource_cost: planner::Budget {
					compute: 2,
					feedback: 2,
				},
				utility_cost: declared.complete_verification_utility_cost,
				outcomes: vec![
					planner::Outcome {
						probability: declared.verification_pass_probability,
						next_state: 2,
						observation: "fixed_quality_and_fresh_restore_pass".into(),
					},
					planner::Outcome {
						probability: 1.0 - declared.verification_pass_probability,
						next_state: 3,
						observation: "verification_does_not_qualify".into(),
					},
				],
			}],
		},
		planner::DecisionState {
			id: "verified_pass".into(),
			phase: planner::Phase::VerifiedCandidate,
			verified_use_gain: declared.use_gain_if_verified,
			actions: Vec::new(),
		},
		planner::DecisionState {
			id: "verified_nonqualification".into(),
			phase: planner::Phase::VerifiedCandidate,
			verified_use_gain: 0.0,
			actions: Vec::new(),
		},
	];
	Ok(planner::FiniteLaw {
		schema: "hepta.finite-edit-law.v1".into(),
		cost_unit: declared.utility_unit.clone(),
		information_scope: declared.information_scope.clone(),
		initial_state: 0,
		states,
	})
}

pub(in crate::mcp) fn program(
	request: &Request,
	binding: &ExecutionBinding,
	planner_source: &str,
	adapter_source: &str,
) -> Result<Value> {
	ensure!(
		crate::mcp::weight_config::valid_sha256(planner_source)
			&& crate::mcp::weight_config::valid_sha256(adapter_source),
		"native planner and binding source identities required"
	);
	let law = law(request, binding)?;
	let bounds = work(&law, request.budget)?;
	let mut value = json!({
		"schema":"hepta.smallhcsn.bound-finite-program.v1",
		"request_sha256":digest(&serde_json::to_vec(request)?),
		"law_sha256":digest(&serde_json::to_vec(&law)?),"execution_binding":binding,
		"planner_source_sha256":planner_source,"adapter_source_sha256":adapter_source,
		"work_admission":bounds,"maximum_weighted_successors":MAX_WEIGHTED_SUCCESSORS,
		"maximum_memory_cells":MAX_MEMORY_CELLS,"whole_roundtrip_reservation":reservation(),
		"arithmetic_scope":ARITHMETIC_SCOPE,"probability_sum_tolerance":1e-12,"incumbent_tie_tolerance":1e-12,
		"calibration_truth_verified":false,"global_continuous_weight_optimality_verified":false,
		"full_model_forward_calls":0
	});
	value["program_sha256"] = json!(digest(&serde_json::to_vec(&value)?));
	Ok(value)
}

pub(in crate::mcp) fn plan(
	request: &Request,
	binding: &ExecutionBinding,
	adapter_source: &str,
	deadline: Instant,
) -> Result<Value> {
	let started = Instant::now();
	ensure!(
		started < deadline,
		"finite policy deadline exhausted before admission"
	);
	let law = law(request, binding)?;
	let bounds = work(&law, request.budget)?;
	let program = program(request, binding, &implementation(), adapter_source)?;
	ensure!(
		Instant::now() < deadline,
		"finite policy deadline exhausted before existing solve"
	);
	let result = planner::solve(
		&law,
		planner::Budget {
			compute: request.budget.compute,
			feedback: request.budget.feedback,
		},
		None,
	)?;
	ensure!(
		Instant::now() < deadline,
		"bounded original finite solve exceeded the shared preparation deadline"
	);
	let selected_edit = matches!(&result.first_choice,planner::Choice::Execute{action:0,id}
		if id == &law.states[0].actions[0].id);
	let full_reservation_available = request.budget.compute >= 3 && request.budget.feedback >= 3;
	let mandatory_verify = selected_edit && full_reservation_available && result.reachable_policy.iter().any(|point| {
		point.state == 1 && point.budget.compute == request.budget.compute-1
			&& point.budget.feedback == request.budget.feedback-1
			&& matches!(&point.choice,planner::Choice::Execute{action:0,id} if id == &law.states[1].actions[0].id)
	});
	ensure!(
		!selected_edit || mandatory_verify,
		"selected edit lacks its mandatory fully budgeted verification continuation"
	);
	ensure!(
		program["law_sha256"].as_str() == Some(result.law_sha256.as_str())
			&& result.bellman_cells as u64 == bounds.memory_cells,
		"original finite solver identity or work dimensions differ from native admission"
	);
	Ok(json!({
		"schema":"hepta.smallhcsn.bound-finite-plan.v1","program":program,
		"first_choice":result.first_choice,"expected_declared_net_gain":result.expected_net_gain,
		"reachable_policy":result.reachable_policy,"bellman_cells":result.bellman_cells,
		"execution_selected":selected_edit && mandatory_verify,"mandatory_verify_selected":mandatory_verify,
		"full_reservation_available":full_reservation_available,"whole_roundtrip_reserved_on_intent_write":reservation(),
		"planner_invocations":1,"planner_wall_seconds":started.elapsed().as_secs_f64(),
		"cooperative_deadline_checked_before_and_after_bounded_solver":true,
		"arithmetic_scope":ARITHMETIC_SCOPE,"legacy_scope_text_is_not_an_exact_real_certificate":true,
		"model_forward_calls":0,"calibration_truth_verified":false,
		"positive_plan_is_not_task_improvement_evidence":true,
		"retain_is_research_evidence_only_no_activation":true,"production_eligible":false
	}))
}
