// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Analytic joint-ball solutions, represented F32 boundaries and resource refusals.

use super::super::{solve, validate, RidgePlanParams};
use super::*;

fn one(radius: f64) -> RidgePlanParams {
	RidgePlanParams {
		features: vec![vec![1.0]],
		targets: vec![vec![3.0]],
		sample_weights: vec![vec![1.0]],
		base_weights: vec![vec![1.0]],
		lambda: 1.0,
		max_update_l2_norm: Some(radius),
	}
}

fn close(actual: f64, expected: f64) {
	assert!((actual - expected).abs() < 1e-9, "{actual} != {expected}");
}

#[test]
fn scalar_active_ball_has_the_known_solution_and_multiplier() {
	let report = solve(&one(0.25)).unwrap();
	close(report["weights_f64"][0][0].as_f64().unwrap(), 1.25);
	close(
		report["trust_region"]["shared_multiplier"]
			.as_f64()
			.unwrap(),
		6.0,
	);
	assert_eq!(report["trust_region"]["constraint_active"], true);
	assert_eq!(report["f32_update_budget"]["within_budget"], true);
	assert_eq!(report["f32_optimality_certified"], false);
	assert_eq!(
		report["trust_region"]["f64_global_optimality_certified"],
		false
	);
	assert_eq!(report["training_targets_used"], true);
	assert_eq!(report["source_weights_verified"], false);
	assert_eq!(report["gradient_steps"], 0);
	assert!(
		report["operation_charged_units"].as_u64().unwrap()
			<= report["operation_budget_units"].as_u64().unwrap()
	);
}

#[test]
fn differently_weighted_outputs_share_one_joint_radius_and_multiplier() {
	let params = RidgePlanParams {
		features: vec![vec![1.0]],
		targets: vec![vec![14.0, 7.0]],
		sample_weights: vec![vec![1.0, 3.0]],
		base_weights: vec![vec![2.0], vec![-1.0]],
		lambda: 1.0,
		max_update_l2_norm: Some(5.0),
	};
	let report = solve(&params).unwrap();
	close(report["weights_f64"][0][0].as_f64().unwrap(), 5.0);
	close(report["weights_f64"][1][0].as_f64().unwrap(), 3.0);
	close(
		report["trust_region"]["shared_multiplier"]
			.as_f64()
			.unwrap(),
		2.0,
	);
	close(
		report["trust_region"]["f64_update_l2_norm"]
			.as_f64()
			.unwrap(),
		5.0,
	);
	assert!(
		report["trust_region"]["maximum_relative_stationarity_residual_f64"]
			.as_f64()
			.unwrap() < 1e-12
	);
	assert_eq!(report["f32_update_budget"]["within_budget"], true);
	assert_eq!(report["f32_update_budget"]["elements_checked"], 2);
}

#[test]
fn zero_radius_has_singleton_semantics_without_a_fabricated_kkt_multiplier() {
	let params = one(0.0);
	let report = solve(&params).unwrap();
	assert_eq!(report["weights_f64"], json!([[1.0]]));
	assert_eq!(report["weights_f32"], json!([[1.0]]));
	assert_eq!(report["f32_edit_count"], 0);
	assert_eq!(
		report["trust_region"]["singleton_feasibility_verified"],
		true
	);
	assert_eq!(report["trust_region"]["numerical_kkt_checks_passed"], false);
	assert!(report["trust_region"]["shared_multiplier"].is_null());
	assert!(report["trust_region"]["maximum_relative_stationarity_residual_f64"].is_null());
	assert_eq!(report["trust_region"]["shift_solve_batches"], 0);
}

#[test]
fn inactive_radius_matches_the_unconstrained_numerical_solution() {
	let mut params = one(10.0);
	let constrained = solve(&params).unwrap();
	params.max_update_l2_norm = None;
	let original = solve(&params).unwrap();
	close(
		constrained["weights_f64"][0][0].as_f64().unwrap(),
		original["weights_f64"][0][0].as_f64().unwrap(),
	);
	assert_eq!(constrained["trust_region"]["constraint_active"], false);
	assert_eq!(constrained["trust_region"]["shared_multiplier"], 0.0);
	assert!(!serde_json::to_value(&params)
		.unwrap()
		.as_object()
		.unwrap()
		.contains_key("max_update_l2_norm"));
}

#[test]
fn f32_lowering_moves_toward_anchor_before_exact_budget_validation() {
	let mut params = one(0.1);
	params.base_weights = vec![vec![0.0]];
	params.targets = vec![vec![1.0]];
	let report = solve(&params).unwrap();
	let candidate = report["weights_f32"][0][0].as_f64().unwrap();
	assert!(candidate <= 0.1);
	assert!(candidate < f64::from(0.1_f32));
	assert!(candidate > 0.09999);
	assert_eq!(report["f32_update_budget"]["within_budget"], true);
	assert_eq!(
		report["f32_lowering"],
		"toward_anchor_then_exact_dyadic_joint_budget_check"
	);
}

#[test]
fn nonrepresentable_anchors_and_invalid_radii_are_explicit_refusals() {
	for radius in [-1.0, f64::NAN, f64::INFINITY] {
		assert!(solve(&one(radius)).is_err());
	}
	let mut params = one(1.0);
	params.base_weights = vec![vec![0.1]];
	assert!(solve(&params)
		.unwrap_err()
		.to_string()
		.contains("exactly representable"));
	params.max_update_l2_norm = None;
	assert!(solve(&params).is_ok());
}

#[test]
fn multiplier_search_is_reserved_in_the_unchanged_80m_work_budget() {
	let mut params = RidgePlanParams {
		features: vec![vec![0.0; 64]; 2048],
		targets: vec![vec![0.0; 3]; 2048],
		sample_weights: vec![vec![1.0; 3]; 2048],
		base_weights: vec![vec![0.0; 64]; 3],
		lambda: 1.0,
		max_update_l2_norm: Some(1.0),
	};
	assert!(validate(&params)
		.err()
		.unwrap()
		.to_string()
		.contains("work budget"));
	params.max_update_l2_norm = None;
	assert!(validate(&params).is_ok());
	params.max_update_l2_norm = Some(0.0);
	assert!(validate(&params).is_ok());
}

#[test]
fn zero_weight_outputs_preserve_their_anchor_in_a_shared_constrained_solve() {
	let mut params = one(0.25);
	params.targets = vec![vec![3.0, 100.0]];
	params.sample_weights = vec![vec![1.0, 0.0]];
	params.base_weights.push(vec![-0.5]);
	let report = solve(&params).unwrap();
	close(report["weights_f64"][0][0].as_f64().unwrap(), 1.25);
	assert_eq!(report["weights_f64"][1][0], -0.5);
	assert_eq!(report["weights_f32"][1][0], -0.5);
	assert_eq!(report["diagnostics"][1]["positive_weight_rows"], 0);
}
