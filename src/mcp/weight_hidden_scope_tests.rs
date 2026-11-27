// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Synthetic byte admission and analytic inverse controls; no checkpoint or model is executed.

use super::*;
use drift::{CompileParams, F32Realization, Target};
use serde_json::Map;

fn target_source() -> TargetDeclaration {
	TargetDeclaration {
		kind: TargetSourceKind::CallerSpecified,
		source_sha256: "a".repeat(64),
		description: "Synthetic engineering target; no NDU objective claim".into(),
	}
}
fn hex(value: f32) -> String {
	crate::mcp::rea_model::digest_hex(&value.to_le_bytes())
}
fn make_parent() -> Vec<u8> {
	let definitions = [
		("body.raw_cost", "F32", vec![8]),
		("body.raw_boundary", "F32", vec![8]),
		("body.reset_absolute", "F64", vec![8]),
		("body.fixed_boundary", "F64", vec![8]),
		("body.synaptic_mask", "F32", vec![8, 24]),
		("body.recurrent.weight", "F32", vec![8, 24]),
		(WEIGHT_NAME, "F32", vec![4, 9]),
		("body.input_mark.weight", "F32", vec![4, 9]),
		(BIAS_NAME, "F32", vec![4]),
		("body.input_mark.bias", "F32", vec![4]),
		("body.readout.weight", "F32", vec![2, 20]),
		("body.readout.bias", "F32", vec![2]),
	];
	let mut header = Map::new();
	let mut payload = Vec::new();
	for (name, dtype, shape) in definitions {
		let begin = payload.len();
		for _ in 0..shape.iter().product::<usize>() {
			if dtype == "F32" {
				payload.extend_from_slice(&0.25f32.to_le_bytes());
			} else {
				payload.extend_from_slice(&0.25f64.to_le_bytes());
			}
		}
		header.insert(
			name.into(),
			json!({"dtype":dtype,"shape":shape,"data_offsets":[begin,payload.len()]}),
		);
	}
	header.insert("__metadata__".into(), json!({"source_checkpoint_sha256":"b".repeat(64),
        "alias_map_json":json!({"head.weight":"body.readout.weight","head.bias":"body.readout.bias"}).to_string()}));
	let header = serde_json::to_vec(&header).unwrap();
	let mut parent = (header.len() as u64).to_le_bytes().to_vec();
	parent.extend_from_slice(&header);
	parent.extend_from_slice(&payload);
	parent
}
fn header_sha(parent: &[u8]) -> String {
	let size = u64::from_le_bytes(parent[..8].try_into().unwrap()) as usize;
	digest(&parent[8..8 + size])
}
fn fixture(weight: f32, bias: f32, radius: f64) -> (Vec<u8>, Vec<u8>, PlanParams) {
	let parent = make_parent();
	let layout = layout::inspect(&parent, &header_sha(&parent)).unwrap();
	let mut candidate = parent.clone();
	for (name, value) in [(WEIGHT_NAME, weight), (BIAS_NAME, bias)] {
		let offset = layout.offset(name, 0).unwrap();
		candidate[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
	}
	let params = PlanParams {
		scope: EditScope::SenderDriveAndBias,
		parent_sha256: digest(&parent),
		candidate_sha256: digest(&candidate),
		header_sha256: header_sha(&parent),
		input_sha256: "c".repeat(64),
		allowed_coordinates: vec![
			Coordinate::Weight { row: 0, column: 0 },
			Coordinate::Bias { row: 0 },
		],
		edits: vec![
			Edit {
				coordinate: Coordinate::Weight { row: 0, column: 0 },
				expected_hex: hex(0.25),
				replacement_hex: hex(weight),
			},
			Edit {
				coordinate: Coordinate::Bias { row: 0 },
				expected_hex: hex(0.25),
				replacement_hex: hex(bias),
			},
		],
		maximum_update_l2_norm: radius,
		target_source: target_source(),
		identity: cohort::Identity {
			code_sha256: "d".repeat(64),
			tensor_map_sha256: "e".repeat(64),
			data_manifest_sha256: "f".repeat(64),
			objective_sha256: "0".repeat(64),
			dependency_manifest_sha256: "1".repeat(64),
		},
	};
	(parent, candidate, params)
}

#[test]
fn actual_bytes_admit_two_sender_members_and_reuse_owner_contract() {
	let (parent, candidate, params) = fixture(0.375, 0.125, 0.25);
	let plan = prepare(&params, &parent).unwrap();
	assert_eq!(plan.evidence()["actual_candidate_verified"], false);
	let admitted = plan.admit(&candidate).unwrap();
	assert_eq!((admitted.weight[0], admitted.bias[0]), (0.375, 0.125));
	assert_eq!(admitted.evidence["all_other_bytes_preserved"], true);
	assert_eq!(admitted.evidence["target_is_proved_ndu_objective"], false);
	let request = plan
		.cohort_request("/isolated/canonical.safetensors".into(), "2".repeat(64))
		.unwrap();
	assert_eq!(request.members.len(), 2);
	assert_eq!(request.expected_sha256, digest(&parent));
	assert_eq!(request.members[0].tensor_name, WEIGHT_NAME);
	assert_eq!(request.members[1].tensor_name, BIAS_NAME);
	assert_eq!(
		request.identity.dependency_manifest_sha256,
		plan.request_sha256
	);
	assert_eq!(
		request.identity.objective_sha256,
		digest(&serde_json::to_vec(&params.target_source).unwrap())
	);
	assert!(matches!(
		request.training,
		cohort::TrainingContract::InferenceOnly
	));
}

#[test]
fn complete_sha_and_exact_before_bytes_cannot_be_substituted() {
	let (parent, candidate, mut params) = fixture(0.375, 0.25, 0.125);
	let plan = prepare(&params, &parent).unwrap();
	let mut bad = candidate.clone();
	let head = layout::inspect(&parent, &params.header_sha256)
		.unwrap()
		.offset("body.readout.weight", 0)
		.unwrap();
	bad[head..head + 4].copy_from_slice(&0.5f32.to_le_bytes());
	assert!(plan.admit(&bad).is_err());
	params.candidate_sha256 = digest(&bad);
	assert!(prepare(&params, &parent).is_err());
	params.candidate_sha256 = digest(&candidate);
	params.edits[0].expected_hex = hex(0.0);
	assert!(prepare(&params, &parent).is_err());
	params.edits[0].expected_hex = hex(0.25);
	params.parent_sha256 = "0".repeat(64);
	assert!(prepare(&params, &parent).is_err());
}

#[test]
fn declared_scope_rejects_duplicates_missing_members_and_extra_sites() {
	let (parent, _, original) = fixture(0.375, 0.25, 0.125);
	let mut params = original.clone();
	params
		.allowed_coordinates
		.push(params.allowed_coordinates[0].clone());
	assert!(prepare(&params, &parent).is_err());
	params = original.clone();
	params.edits.push(params.edits[0].clone());
	assert!(prepare(&params, &parent).is_err());
	params = original.clone();
	params.edits[1].coordinate = Coordinate::Weight { row: 1, column: 0 };
	params
		.allowed_coordinates
		.push(params.edits[1].coordinate.clone());
	assert!(prepare(&params, &parent).is_err());
	params = original;
	params.allowed_coordinates[0] = Coordinate::Weight { row: 4, column: 0 };
	assert!(prepare(&params, &parent).is_err());
	assert!(
		serde_json::from_value::<Coordinate>(json!({"tensor":"readout","row":0,"column":0}))
			.is_err()
	);
	assert!(serde_json::from_value::<EditScope>(json!("arbitrary_tensor")).is_err());
}

#[test]
fn exact_f32_budget_includes_bias_and_allows_an_explicit_noop_member() {
	let (parent, candidate, mut params) = fixture(0.375, 0.25, 0.125);
	assert!(prepare(&params, &parent).unwrap().admit(&candidate).is_ok());
	params.maximum_update_l2_norm = f64::from_bits(0.125f64.to_bits() - 1);
	assert!(prepare(&params, &parent).is_err());
	let (parent, _, params) = fixture(0.375, 0.375, 0.125);
	assert!(prepare(&params, &parent).is_err());
	let (parent, candidate, params) = fixture(0.25, 0.25, 0.0);
	assert!(prepare(&params, &parent).unwrap().admit(&candidate).is_ok());
}

#[test]
fn malformed_hex_nonfinite_values_and_expired_work_fail_before_admission() {
	let (parent, _, original) = fixture(0.375, 0.25, 0.125);
	for hex in ["0000807f", "0000c07f", "000080FF", "0000", "zzzzzzzz"] {
		let mut params = original.clone();
		params.edits[0].replacement_hex = hex.into();
		assert!(prepare(&params, &parent).is_err());
	}
	assert!(
		prepare_with_deadline(&original, &parent, Instant::now() - Duration::from_secs(1)).is_err()
	);
}

#[test]
fn layout_changes_and_alias_substitution_are_not_sender_edits() {
	let (parent, _, mut params) = fixture(0.375, 0.25, 0.125);
	let size = u64::from_le_bytes(parent[..8].try_into().unwrap()) as usize;
	let original: Value = serde_json::from_slice(&parent[8..8 + size]).unwrap();
	for alias_change in [false, true] {
		let mut header = original.clone();
		if alias_change {
			header["__metadata__"]["alias_map_json"] = json!("{}");
		} else {
			header[WEIGHT_NAME]["shape"] = json!([4, 8]);
		}
		let header = serde_json::to_vec(&header).unwrap();
		let mut changed = (header.len() as u64).to_le_bytes().to_vec();
		changed.extend_from_slice(&header);
		changed.extend_from_slice(&parent[8 + size..]);
		params.parent_sha256 = digest(&changed);
		params.header_sha256 = digest(&header);
		assert!(prepare(&params, &changed).is_err());
	}
}

fn drift_params(desired: f64, policy: F32Realization) -> CompileParams {
	CompileParams {
		parent_sha256: "3".repeat(64),
		input_sha256: "4".repeat(64),
		target_source: target_source(),
		f32_realization: policy,
		targets: vec![Target {
			query: 0,
			choice: 1,
			tick: 2,
			sender: 0,
			desired_drift: desired,
		}],
	}
}

#[test]
fn closed_inverse_reports_real_and_actual_f32_semantics_separately() {
	let base = -0.2f32 as f64;
	let scale = 0.15f32 as f64;
	let expected_pre = 0.7f64;
	let target = base + scale * expected_pre.tanh();
	let output = drift::compile(&drift_params(target, F32Realization::ReportResidual)).unwrap();
	let row = &output["rows"][0];
	assert!((row["preactivation_f64"].as_f64().unwrap() - expected_pre).abs() < 2e-15);
	assert!(
		row["real_inverse_reconstruction_residual"]
			.as_f64()
			.unwrap()
			.abs() < 2e-15
	);
	assert!(row["f32_residual"].as_f64().unwrap().abs() < 2e-7);
	assert_eq!(output["target_is_proved_ndu_objective"], false);
	assert_eq!(output["shared_weight_solution_computed"], false);
	let center = drift::compile(&drift_params(base, F32Realization::RequireBitExact)).unwrap();
	assert_eq!(center["rows"][0]["actual_f32_target_bit_exact"], true);
	assert_eq!(center["rows"][0]["preactivation_f32_le_hex"], "00000000");
}

#[test]
fn infeasible_interior_targets_do_not_trigger_clipping_or_rounding_search() {
	let base = -0.2f32 as f64;
	let scale = 0.15f32 as f64;
	for target in [base - scale, base + scale, 1.0, f64::NAN, f64::INFINITY] {
		assert!(drift::compile(&drift_params(target, F32Realization::ReportResidual)).is_err());
	}
	let unrepresentable = base + scale * 0.7f64.tanh();
	assert!(drift::compile(&drift_params(
		unrepresentable,
		F32Realization::RequireBitExact
	))
	.is_err());
	let mut params = drift_params(base, F32Realization::ReportResidual);
	params.targets.push(params.targets[0].clone());
	assert!(drift::compile(&params).is_err());
	params.targets.pop();
	params.targets[0].tick = 1;
	assert!(drift::compile(&params).is_err());
	params.targets[0].tick = 0;
	assert!(
		drift::compile_with_deadline(&params, Instant::now() - Duration::from_secs(1)).is_err()
	);
	let invalid = json!({"kind":"proved_ndu_optimum","source_sha256":"0".repeat(64),"description":"caller claim"});
	assert!(serde_json::from_value::<TargetDeclaration>(invalid).is_err());
}
