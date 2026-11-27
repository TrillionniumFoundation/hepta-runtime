// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bind a conditional policy to the actual proposal and original cohort intent.
//! Serialized policy evidence is neither session authority nor a replacement journal.

use super::*;
use crate::mcp::weight_smallhcsn_ndu as finite;

pub(super) fn implementation() -> String {
	digest(include_bytes!("weight_artifact_smallhcsn_ndu.rs"))
}

fn quality_contract(input: &Input) -> Value {
	json!({
		"schema":"hepta.smallhcsn.fixed-quality-contract.v1",
		"minimum_mse_gain":input.minimum_mse_gain,"correct_count_may_decrease":false,
		"maximum_physical_residual":2e-9,"restored_output_bytes_equal_parent":true,
		"session_authority_required_after_inverse":true,"all_errors_absent":true,
		"zero_threshold_allows_noop":true,"production_activation":false
	})
}

pub(super) fn execution_binding(
	input: &Input,
	compiler_source: &str,
	evaluator: &str,
	attempt_budget: &Value,
) -> Result<finite::ExecutionBinding> {
	let proposal = input
		.proposal
		.as_ref()
		.context("finite execution requires the actual native sender proposal")?;
	let program = compiler::program(
		proposal,
		&digest(input.profile_json.as_bytes()),
		compiler_source,
		evaluator,
	)?;
	Ok(finite::ExecutionBinding {
		parent_sha256: input.plan.parent_sha256.clone(),
		profile_sha256: digest(input.profile_json.as_bytes()),
		raw_input_sha256: input.plan.input_sha256.clone(),
		plan_sha256: digest(&serde_json::to_vec(&input.plan)?),
		candidate_sha256: input.plan.candidate_sha256.clone(),
		proposal_program_sha256: program["program_sha256"]
			.as_str()
			.context("native proposal identity")?
			.into(),
		evaluator_sha256: evaluator.into(),
		attempt_budget_sha256: digest(&serde_json::to_vec(attempt_budget)?),
		quality_contract_sha256: digest(&serde_json::to_vec(&quality_contract(input))?),
	})
}

pub(super) fn bound_program(input: &Input) -> Result<Option<Value>> {
	let Some(request) = &input.ndu else {
		return Ok(None);
	};
	let execution = execution_binding(
		input,
		&compiler::compiler_identity(),
		&model::evaluator_identity(),
		&budget(),
	)?;
	Ok(Some(finite::program(
		request,
		&execution,
		&finite::implementation(),
		&implementation(),
	)?))
}

pub(super) fn select(
	input: &Input,
	proposal_evidence: &Value,
	end: std::time::Instant,
) -> Result<Value> {
	let Some(request) = &input.ndu else {
		return Ok(Value::Null);
	};
	ensure!(
		proposal_evidence["actual_parent_words_and_raw_keys_verified"] == true
			&& proposal_evidence["plan_sha256"] == digest(&serde_json::to_vec(&input.plan)?)
			&& proposal_evidence["candidate_sha256"] == input.plan.candidate_sha256,
		"finite policy must follow native source-bound proposal recompilation"
	);
	let binding = execution_binding(
		input,
		&compiler::compiler_identity(),
		&model::evaluator_identity(),
		&budget(),
	)?;
	finite::plan(request, &binding, &implementation(), end)
}

pub(super) fn seal(evidence: &Value, id: &str) -> Result<Value> {
	if evidence.is_null() {
		return Ok(Value::Null);
	}
	ensure!(
		evidence["execution_selected"] == true
			&& evidence["mandatory_verify_selected"] == true
			&& evidence["full_reservation_available"] == true,
		"STOP or an incompletely budgeted finite policy cannot become an effect intent"
	);
	let mut value = evidence.clone();
	value["original_request_id"] = json!(id);
	value["upfront_reservation"] = finite::reservation();
	value["upfront_reservation"]["charged_by_original_intent"] = json!(true);
	value["upfront_reservation"]["original_request_id"] = json!(id);
	Ok(value)
}

pub(super) fn validate_saved(
	input: &Input,
	proposal_evidence: &Value,
	evidence: &Value,
	evaluator: &str,
	attempt_budget: &Value,
	id: &str,
) -> Result<Option<Value>> {
	let Some(request) = &input.ndu else {
		ensure!(
			evidence.is_null(),
			"an unplanned attempt cannot impersonate a finite-policy reservation"
		);
		return Ok(None);
	};
	let compiler_source = proposal_evidence["program"]["compiler_source_sha256"]
		.as_str()
		.context("original finite policy is missing its native compiler source")?;
	let planner_source = evidence["program"]["planner_source_sha256"]
		.as_str()
		.context("original finite policy is missing its planner source")?;
	let adapter_source = evidence["program"]["adapter_source_sha256"]
		.as_str()
		.context("original finite policy is missing its binding source")?;
	let binding = execution_binding(input, compiler_source, evaluator, attempt_budget)?;
	let expected = finite::program(request, &binding, planner_source, adapter_source)?;
	let mut reserved = finite::reservation();
	reserved["charged_by_original_intent"] = json!(true);
	reserved["original_request_id"] = json!(id);
	ensure!(
		evidence["schema"] == "hepta.smallhcsn.bound-finite-plan.v1"
			&& evidence["program"] == expected
			&& evidence["original_request_id"] == id
			&& evidence["upfront_reservation"] == reserved
			&& evidence["execution_selected"] == true
			&& evidence["mandatory_verify_selected"] == true
			&& evidence["full_reservation_available"] == true
			&& request.budget.compute >= 3
			&& request.budget.feedback >= 3
			&& evidence["planner_invocations"] == 1
			&& evidence["model_forward_calls"] == 0
			&& evidence["planner_wall_seconds"]
				.as_f64()
				.is_some_and(|seconds| seconds.is_finite() && seconds >= 0.0),
		"saved finite policy differs from its original source-bound complete reservation"
	);
	// Do not rerun a historical policy or proposal during inverse recovery. The original
	// intent digest binds this native receipt, while the same owner performs exact undo.
	Ok(Some(expected))
}

pub(super) fn observed(evidence: &Value, qualified: bool, complete: bool) -> Value {
	if evidence.is_null() {
		return Value::Null;
	}
	json!({
		"schema":"hepta.smallhcsn.finite-observation.v1",
		"program_sha256":evidence["program"]["program_sha256"],
		"observation":if qualified {"fixed_quality_and_fresh_restore_pass"}
			else if complete {"verification_does_not_qualify"} else {"incomplete_or_interrupted_stop"},
		"upfront_reservation":evidence["upfront_reservation"],
		"declared_expected_gain":evidence["expected_declared_net_gain"],
		"actual_utility_gain_verified":false,"calibration_truth_verified":false,
		"unused_reservation_refunded":false,"remaining_declared_budget_authorizes_new_attempt":false,
		"new_planner_invocations":0,"candidate_remains_active":false
	})
}
