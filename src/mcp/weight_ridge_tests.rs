// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Known solutions, numerical refusals, F32 patch fidelity and opt-in real fixture parity.

use super::*;

fn known() -> RidgePlanParams {
	RidgePlanParams {
		features: vec![vec![1.0, 0.0], vec![0.0, 1.0]],
		targets: vec![vec![3.0], vec![-1.0]],
		sample_weights: vec![vec![1.0], vec![3.0]],
		base_weights: vec![vec![1.0, 2.0]],
		lambda: 1.0,
		max_update_l2_norm: None,
	}
}

fn weights(result: &Value, key: &str) -> Vec<Vec<f64>> {
	serde_json::from_value(result[key].clone()).unwrap()
}

fn close(actual: f64, expected: f64, tolerance: f64) {
	assert!(
		(actual - expected).abs() <= tolerance,
		"actual {actual}, expected {expected}"
	);
}

fn verify_patch(params: &RidgePlanParams, report: &Value) {
	let edits: Vec<ExactElementEdit> =
		serde_json::from_value(report["f32_element_edits"].clone()).unwrap();
	let mut bytes: Vec<u8> = params
		.base_weights
		.iter()
		.flatten()
		.flat_map(|x| (*x as f32).to_le_bytes())
		.collect();
	for edit in &edits {
		let start = edit.index as usize * 4;
		let expected = super::super::weight_tensor::unhex(&edit.expected_hex).unwrap();
		let replacement = super::super::weight_tensor::unhex(&edit.replacement_hex).unwrap();
		assert_eq!(&bytes[start..start + 4], expected);
		bytes[start..start + 4].copy_from_slice(&replacement);
	}
	let returned: Vec<Vec<f32>> = serde_json::from_value(report["weights_f32"].clone()).unwrap();
	let expected: Vec<u8> = returned
		.iter()
		.flatten()
		.flat_map(|x| x.to_le_bytes())
		.collect();
	assert_eq!(bytes, expected);
	assert_eq!(report["f32_edit_count"], edits.len());
}

#[test]
fn known_proximal_solution_and_exact_f32_patch() {
	let params = known();
	let report = solve(&params).unwrap();
	let found = weights(&report, "weights_f64");
	close(found[0][0], 2.0, 1e-14);
	close(found[0][1], -0.25, 1e-14);
	close(
		report["diagnostics"][0]["objective_before_f64"]
			.as_f64()
			.unwrap(),
		31.0,
		1e-13,
	);
	close(
		report["diagnostics"][0]["objective_after_f64"]
			.as_f64()
			.unwrap(),
		8.75,
		1e-13,
	);
	assert!(
		report["diagnostics"][0]["relative_normal_equation_residual_f64"]
			.as_f64()
			.unwrap() < 1e-14
	);
	assert_eq!(report["training_targets_used"], true);
	assert_eq!(report["gradient_steps"], 0);
	assert_eq!(report["production_eligible"], false);
	assert_eq!(report["source_weights_verified"], false);
	verify_patch(&params, &report);
}

#[test]
fn each_output_uses_its_own_sample_weights_without_row_normalization() {
	let params = RidgePlanParams {
		features: vec![vec![1.0], vec![1.0]],
		targets: vec![vec![2.0, 8.0], vec![10.0, 4.0]],
		sample_weights: vec![vec![1.0, 0.0], vec![0.0, 3.0]],
		base_weights: vec![vec![0.0], vec![0.0]],
		lambda: 1.0,
		max_update_l2_norm: None,
	};
	let report = solve(&params).unwrap();
	let found = weights(&report, "weights_f64");
	close(found[0][0], 1.0, 1e-14);
	close(found[1][0], 3.0, 1e-14);
	verify_patch(&params, &report);
}

#[test]
fn positive_lambda_solves_rank_deficiency_and_zero_weight_rows_preserve_anchor() {
	let mut params = RidgePlanParams {
		features: vec![vec![1.0, 1.0], vec![2.0, 2.0]],
		targets: vec![vec![2.0], vec![4.0]],
		sample_weights: vec![vec![1.0], vec![1.0]],
		base_weights: vec![vec![0.0, 0.0]],
		lambda: 1.0,
		max_update_l2_norm: None,
	};
	let report = solve(&params).unwrap();
	for value in &weights(&report, "weights_f64")[0] {
		close(*value, 10.0 / 11.0, 1e-14);
	}
	params.sample_weights = vec![vec![0.0], vec![0.0]];
	params.base_weights = vec![vec![0.125, -0.75]];
	params.lambda = 1e-200;
	let report = solve(&params).unwrap();
	assert_eq!(weights(&report, "weights_f64"), params.base_weights);
	assert_eq!(report["f32_edit_count"], 0);
	assert_eq!(report["diagnostics"][0]["positive_weight_rows"], 0);
	assert_eq!(
		report["diagnostics"][0]["f32_objective_strictly_improved"],
		false
	);
}

#[test]
fn f64_improvement_can_disappear_when_exported_to_f32() {
	let params = RidgePlanParams {
		features: vec![vec![1.0]],
		targets: vec![vec![1.0 + 1e-8]],
		sample_weights: vec![vec![1.0]],
		base_weights: vec![vec![1.0]],
		lambda: 1.0,
		max_update_l2_norm: None,
	};
	let report = solve(&params).unwrap();
	assert!(weights(&report, "weights_f64")[0][0] > 1.0);
	assert_eq!(weights(&report, "weights_f32"), vec![vec![1.0]]);
	assert_eq!(report["f32_edit_count"], 0);
	assert_eq!(
		report["diagnostics"][0]["f32_objective_strictly_improved"],
		false
	);
	verify_patch(&params, &report);
}

#[test]
fn malformed_dimensions_values_and_penalties_are_rejected() {
	for case in 0..14 {
		let mut params = known();
		match case {
			0 => params.features.clear(),
			1 => params.features[0].clear(),
			2 => params.features[0] = vec![0.0; 65],
			3 => params.features = vec![vec![0.0; 2]; 2049],
			4 => params.base_weights = vec![vec![0.0; 2]; 9],
			5 => params.targets.pop().map(|_| ()).unwrap(),
			6 => params.sample_weights[0].clear(),
			7 => params.features[0][0] = f64::NAN,
			8 => params.targets[0][0] = f64::INFINITY,
			9 => params.sample_weights[0][0] = -1.0,
			10 => params.sample_weights[0][0] = f64::NAN,
			11 => params.base_weights[0][0] = f64::MAX,
			12 => params.lambda = 0.0,
			13 => params.lambda = f64::NAN,
			_ => unreachable!(),
		}
		assert!(solve(&params).is_err(), "invalid case {case} was accepted");
	}
	assert!(serde_json::from_value::<RidgePlanParams>(json!({"features":[[1]],"targets":[[1]],"sample_weights":[[1]],"base_weights":[[0]],"lambda":1,"hidden":true})).is_err());
}

#[test]
fn overflow_unrepresentable_candidates_and_lost_positive_definiteness_fail_closed() {
	let mut params = RidgePlanParams {
		features: vec![vec![1e200]],
		targets: vec![vec![1.0]],
		sample_weights: vec![vec![1.0]],
		base_weights: vec![vec![0.0]],
		lambda: 1.0,
		max_update_l2_norm: None,
	};
	assert!(solve(&params).unwrap_err().to_string().contains("overflow"));
	params.features = vec![vec![1.0]];
	params.targets = vec![vec![1e40]];
	assert!(solve(&params)
		.unwrap_err()
		.to_string()
		.contains("finite F32"));
	params.features = vec![vec![1.0, 1.0]];
	params.targets = vec![vec![1.0]];
	params.base_weights = vec![vec![0.0, 0.0]];
	params.lambda = 1e-320;
	assert!(solve(&params)
		.unwrap_err()
		.to_string()
		.contains("positive definiteness"));
}

#[tokio::test]
async fn async_planner_returns_the_same_mathematical_candidate() {
	let report: Value = serde_json::from_str(&plan(known()).await.unwrap()).unwrap();
	close(weights(&report, "weights_f64")[0][0], 2.0, 1e-14);
	assert_eq!(
		report["requires_pinned_source_and_guarded_evaluation"],
		true
	);
}

#[test]
#[ignore = "requires HEPTA_WEIGHT_RIDGE_FIXTURE pointing to the separately authorized actual-head NumPy fixture"]
fn actual_head_fixture_matches_independent_numpy_weights() {
	let path = std::path::PathBuf::from(
		std::env::var("HEPTA_WEIGHT_RIDGE_FIXTURE").expect("explicit local fixture path"),
	);
	assert!(path.is_absolute());
	let bytes = std::fs::read(path).unwrap();
	let fixture: Value = serde_json::from_slice(&bytes).unwrap();
	assert_eq!(
		fixture["schema"],
		"hepta-real-head-proximal-ridge-fixture-v1"
	);
	let params:RidgePlanParams=serde_json::from_value(json!({"features":fixture["features"],"targets":fixture["targets"],"sample_weights":fixture["sample_weights"],"base_weights":fixture["base_weights"],"lambda":fixture["lambda_"]})).unwrap();
	let expected: Vec<Vec<f64>> =
		serde_json::from_value(fixture["expected_weights"].clone()).unwrap();
	assert_eq!(expected.len(), params.base_weights.len());
	assert!(expected
		.iter()
		.all(|row| row.len() == params.features[0].len()));
	let report = solve(&params).unwrap();
	let mut errors = Vec::new();
	for (key, tolerance) in [("weights_f64", 1e-10), ("weights_f32", 1e-6)] {
		let found = weights(&report, key);
		let error = found
			.iter()
			.flatten()
			.zip(expected.iter().flatten())
			.map(|(a, b)| (a - b).abs())
			.fold(0.0_f64, f64::max);
		assert!(error <= tolerance, "{key} differs from NumPy by {error}");
		errors.push((key, error));
	}
	verify_patch(&params, &report);
	println!(
		"WEIGHT_PROXIMAL_RIDGE_NUMPY_QUALIFICATION {}",
		json!({"fixture_sha256":Sha256::digest(&bytes).iter().map(|byte|format!("{byte:02x}")).collect::<String>(),"source_model_sha256":fixture["source_model_sha256"],"rows":report["rows"],"features":report["features"],"outputs":report["outputs"],"max_absolute_errors":errors,"exact_f32_patch_verified":true,"gradient_steps":0,"training_targets_used":true,"production_eligible":false,"scope":"actual linear-head supervised fitting parity; no circuit discovery or end-to-end improvement proof"})
	);
}
