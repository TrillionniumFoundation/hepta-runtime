// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! The existing finite recursion, exact action mapping and bounded whole-attempt costs.

use super::*;
use std::time::Duration;

fn binding() -> ExecutionBinding {
	ExecutionBinding {
		parent_sha256: "0".repeat(64),
		profile_sha256: "1".repeat(64),
		raw_input_sha256: "2".repeat(64),
		plan_sha256: "3".repeat(64),
		candidate_sha256: "4".repeat(64),
		proposal_program_sha256: "5".repeat(64),
		evaluator_sha256: "6".repeat(64),
		attempt_budget_sha256: "7".repeat(64),
		quality_contract_sha256: "8".repeat(64),
	}
}

fn request() -> Request {
	Request {
		law: DeclaredLaw {
			information_scope: "synthetic conditional law only".into(),
			utility_unit: "declared_synthetic_utility".into(),
			calibration_sha256: "9".repeat(64),
			verification_pass_probability: 0.8,
			use_gain_if_verified: 2.0,
			analytic_edit_utility_cost: 0.1,
			complete_verification_utility_cost: 0.2,
		},
		budget: Budget {
			compute: 3,
			feedback: 3,
		},
		expected_execution: binding(),
	}
}

fn solve(request: &Request) -> Result<Value> {
	plan(
		request,
		&binding(),
		&"a".repeat(64),
		Instant::now() + Duration::from_secs(5),
	)
}

#[test]
fn selected_analytic_action_requires_the_fully_budgeted_verify_continuation() {
	let mut request = request();
	let value = solve(&request).unwrap();
	assert_eq!(value["execution_selected"], true);
	assert_eq!(value["mandatory_verify_selected"], true);
	assert_eq!(value["program"]["work_admission"]["memory_cells"], 64);
	assert_eq!(
		value["program"]["work_admission"]["weighted_successor_upper_bound"],
		48
	);
	assert_eq!(
		value["whole_roundtrip_reserved_on_intent_write"]["compute_units"],
		3
	);
	assert_eq!(
		value["whole_roundtrip_reserved_on_intent_write"]["feedback_units"],
		3
	);
	for budget in [
		Budget {
			compute: 2,
			feedback: 3,
		},
		Budget {
			compute: 3,
			feedback: 2,
		},
		Budget {
			compute: 1,
			feedback: 1,
		},
	] {
		request.budget = budget;
		let stopped = solve(&request).unwrap();
		assert_eq!(stopped["first_choice"]["kind"], "stop");
		assert_eq!(stopped["execution_selected"], false);
		assert_eq!(stopped["full_reservation_available"], false);
	}
}

#[test]
fn positive_sub_tolerance_declared_gain_keeps_stop_in_the_original_f64_solver() {
	let mut request = request();
	request.law.verification_pass_probability = 1.0;
	request.law.use_gain_if_verified = 1e-13;
	request.law.analytic_edit_utility_cost = 0.0;
	request.law.complete_verification_utility_cost = 0.0;
	let value = solve(&request).unwrap();
	assert_eq!(value["first_choice"]["kind"], "stop");
	assert_eq!(value["expected_declared_net_gain"], 0.0);
	assert_eq!(value["execution_selected"], false);
	assert_eq!(value["arithmetic_scope"], ARITHMETIC_SCOPE);
	assert_eq!(
		value["legacy_scope_text_is_not_an_exact_real_certificate"],
		true
	);
}

#[test]
fn each_candidate_evaluator_budget_and_objective_mapping_pin_is_enforced() {
	let request = request();
	for key in [
		"parent_sha256",
		"profile_sha256",
		"raw_input_sha256",
		"plan_sha256",
		"candidate_sha256",
		"proposal_program_sha256",
		"evaluator_sha256",
		"attempt_budget_sha256",
		"quality_contract_sha256",
	] {
		let mut changed = serde_json::to_value(binding()).unwrap();
		changed[key] = json!("f".repeat(64));
		let changed: ExecutionBinding = serde_json::from_value(changed).unwrap();
		assert!(
			plan(
				&request,
				&changed,
				&"a".repeat(64),
				Instant::now() + Duration::from_secs(5)
			)
			.is_err(),
			"{key}"
		);
	}
}

#[test]
fn checked_work_rejects_large_memory_weighted_work_and_integer_overflow() {
	assert!(checked_work(65_536, 1, 0, 0).is_ok());
	assert!(checked_work(65_537, 1, 0, 0).is_err());
	assert!(checked_work(1, 1_048_576, 0, 0).is_ok());
	assert!(checked_work(1, 1_048_577, 0, 0).is_err());
	assert!(checked_work(1, 1, u64::MAX, 0).is_err());
	assert!(checked_work(1, u64::MAX, 1, 0).is_err());
	assert!(checked_work(u64::MAX, 1, 1, 0).is_err());
	let mut request = request();
	request.budget.compute = 129;
	assert!(solve(&request).is_err());
}

#[test]
fn policy_program_commits_declared_law_calibration_and_source_without_an_intent_cycle() {
	let request = request();
	let first = program(&request, &binding(), &"a".repeat(64), &"b".repeat(64)).unwrap();
	assert!(first.get("original_request_id").is_none());
	let mut changed = request.clone();
	changed.law.calibration_sha256 = "c".repeat(64);
	let second = program(&changed, &binding(), &"a".repeat(64), &"b".repeat(64)).unwrap();
	assert_ne!(first["program_sha256"], second["program_sha256"]);
	assert_eq!(
		first["law_sha256"], second["law_sha256"],
		"calibration identity is not a changed transition law"
	);
	changed.law.verification_pass_probability = 0.7;
	let third = program(&changed, &binding(), &"a".repeat(64), &"b".repeat(64)).unwrap();
	assert_ne!(first["law_sha256"], third["law_sha256"]);
	let source = program(&request, &binding(), &"d".repeat(64), &"b".repeat(64)).unwrap();
	assert_ne!(first["program_sha256"], source["program_sha256"]);
	assert_eq!(first["calibration_truth_verified"], false);
}

#[test]
fn invalid_declared_cost_probability_and_deadline_fail_before_execution_selection() {
	for probability in [-0.1, 1.1, f64::NAN, f64::INFINITY] {
		let mut request = request();
		request.law.verification_pass_probability = probability;
		assert!(solve(&request).is_err());
	}
	for cost in [-1.0, f64::NAN, f64::INFINITY, 1e7] {
		let mut request = request();
		request.law.complete_verification_utility_cost = cost;
		assert!(solve(&request).is_err());
	}
	assert!(plan(&request(), &binding(), &"a".repeat(64), Instant::now()).is_err());
}
