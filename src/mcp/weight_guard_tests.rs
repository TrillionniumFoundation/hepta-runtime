// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Real file tests for adjudication, semantic rejection and exact reverse publication.

use super::super::weight_tensor::ExactElementEdit;
use super::*;

async fn fixture(
	weights: &[f32],
	width: usize,
) -> (tempfile::TempDir, GuardedPatchParams, Vec<u8>) {
	let temp = tempfile::tempdir().unwrap();
	let path = temp.path().join("parent.safetensors");
	let mut header = serde_json::to_vec(&json!({"weight":{"dtype":"F32","shape":[weights.len()/width,width],"data_offsets":[0,weights.len()*4]}})).unwrap();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
	bytes.extend(header);
	for value in weights {
		bytes.extend(value.to_le_bytes());
	}
	tokio::fs::write(&path, &bytes).await.unwrap();
	let params = GuardedPatchParams {
		patch: PatchTensorParams {
			path: path.to_string_lossy().into_owned(),
			expected_sha256: digest(&bytes),
			tensor_name: "weight".into(),
			edits: vec![ExactElementEdit {
				index: 0,
				expected_hex: element(weights[0]),
				replacement_hex: element(2.0),
			}],
		},
		inputs: vec![vec![-2., 1.], vec![0.5, 2.], vec![3., -1.]],
		bias: None,
		objective: Objective::SquaredError {
			targets: vec![vec![-7.], vec![-5.], vec![9.]],
		},
		minimum_gain: 0.0,
		constraints: Vec::new(),
	};
	(temp, params, bytes)
}

fn element(value: f32) -> String {
	value
		.to_le_bytes()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

async fn run(temp: &tempfile::TempDir, params: GuardedPatchParams) -> Value {
	evaluate_with_roots(
		params,
		&[temp.path().to_owned()],
		&temp.path().join("state"),
	)
	.await
	.unwrap()
}

#[tokio::test]
async fn positive_edit_is_evaluated_and_noop_is_not_promoted() {
	let (temp, params, original) = fixture(&[1., -3.], 2).await;
	let passed = run(&temp, params.clone()).await;
	assert_eq!(passed["outcome"], "accepted_on_supplied_rows");
	assert_eq!(passed["primary_after"], 0.0);
	assert_eq!(passed["production_eligible"], false);
	assert!(passed["gain"].as_f64().unwrap() > 4.0);
	let retry = run(&temp, params.clone()).await;
	assert_eq!(passed["evaluation_id"], retry["evaluation_id"]);
	assert_eq!(
		passed["candidate"]["artifact_id"],
		retry["candidate"]["artifact_id"]
	);
	let mut noop = params.clone();
	noop.patch.edits[0].replacement_hex = element(1.0);
	let rejected = run(&temp, noop).await;
	assert_eq!(rejected["outcome"], "rejected_and_restored");
	assert_eq!(rejected["gain"], 0.0);
	assert_eq!(
		rejected["restoration"]["sha256"],
		params.patch.expected_sha256
	);
	assert_eq!(tokio::fs::read(&params.patch.path).await.unwrap(), original);
}

#[tokio::test]
async fn harmful_edit_and_nonfinite_forward_both_restore_every_byte() {
	for replacement in [-2.0, f32::MAX] {
		let (temp, mut params, original) = fixture(&[1., -3.], 2).await;
		params.patch.edits[0].replacement_hex = element(replacement);
		let rejected = run(&temp, params.clone()).await;
		assert_eq!(rejected["outcome"], "rejected_and_restored");
		assert_eq!(rejected["accepted"], false);
		assert_eq!(
			rejected["evaluation_error"].is_null(),
			replacement != f32::MAX
		);
		assert_eq!(
			tokio::fs::read(rejected["restoration"]["artifact_path"].as_str().unwrap())
				.await
				.unwrap(),
			original
		);
		assert_eq!(tokio::fs::read(&params.patch.path).await.unwrap(), original);
	}
}

#[tokio::test]
async fn better_primary_score_cannot_override_preservation_or_terminal_q() {
	let (temp, mut params, _) = fixture(&[1., -3.], 2).await;
	params.constraints.push(Constraint::Preserve {
		column: 0,
		max_absolute_change: 0.0,
	});
	let rejected = run(&temp, params).await;
	assert!(rejected["gain"].as_f64().unwrap() > 0.0);
	assert_eq!(rejected["candidate_constraint_violations"], json!([0]));
	assert_eq!(rejected["outcome"], "rejected_and_restored");
	let (temp, mut params, _) = fixture(&[1., 0., 0., 0., -2., 1., 2., -1.], 2).await;
	params.inputs = vec![vec![0.2, 1.0], vec![0.8, 1.0]];
	params.patch.edits[0].replacement_hex = element(0.5);
	params.objective = Objective::SquaredError {
		targets: vec![vec![0.1, 0., 0.6, -0.6], vec![0.4, 0., -0.6, 0.6]],
	};
	params.constraints = vec![Constraint::TerminalQ {
		belief: 0,
		stop: 1,
		submit_zero: 2,
		submit_one: 3,
		tolerance: 1e-6,
	}];
	let rejected = run(&temp, params).await;
	assert!(rejected["gain"].as_f64().unwrap() > 0.0);
	assert_eq!(rejected["parent_constraint_violations"], json!([]));
	assert_eq!(rejected["candidate_constraint_violations"], json!([0]));
	assert_eq!(rejected["outcome"], "rejected_and_restored");
}

#[tokio::test]
async fn action_value_uses_policy_choice_and_keeps_labels_out_of_forward() {
	let (temp, mut params, _) = fixture(&[1., 0., 0., 1.], 2).await;
	params.inputs = vec![vec![1., 1.5], vec![1., 1.8]];
	params.objective = Objective::ActionValue {
		action_columns: vec![0, 1],
		values: vec![vec![3., -1.], vec![2., 0.]],
	};
	let passed = run(&temp, params.clone()).await;
	assert_eq!(passed["primary_before"], -0.5);
	assert_eq!(passed["primary_after"], 2.5);
	assert_eq!(passed["gain"], 3.0);
	assert_eq!(passed["outcome"], "accepted_on_supplied_rows");
	params.objective = Objective::ActionValue {
		action_columns: vec![0, 1],
		values: vec![vec![-1., 3.], vec![0., 2.]],
	};
	let reversed = run(&temp, params).await;
	assert_eq!(reversed["outcome"], "rejected_and_restored");
	assert_eq!(
		passed["candidate"]["sha256"],
		reversed["candidate"]["sha256"]
	);
	assert_ne!(passed["evaluation_id"], reversed["evaluation_id"]);
}

#[tokio::test]
async fn malformed_labels_constraints_and_unpinned_sources_fail_before_publication() {
	for case in 0..5 {
		let (temp, mut params, _) = fixture(&[1., -3.], 2).await;
		match case {
			0 => {
				params.objective = Objective::SquaredError {
					targets: vec![vec![0.]],
				}
			}
			1 => {
				params.constraints = vec![Constraint::Range {
					column: 9,
					lower: 0.,
					upper: 1.,
				}]
			}
			2 => {
				params.objective = Objective::ActionValue {
					action_columns: vec![0, 0],
					values: vec![vec![1., 0.]; 3],
				}
			}
			3 => params.patch.expected_sha256 = "0".repeat(64),
			4 => params.inputs = vec![vec![f32::MAX; 4096]; 64],
			_ => unreachable!(),
		}
		assert!(evaluate_with_roots(
			params,
			&[temp.path().to_owned()],
			&temp.path().join("state")
		)
		.await
		.is_err());
		assert!(!temp.path().join("state/weight-artifacts-v1").exists());
	}
}

#[tokio::test]
async fn exhausted_restore_budget_is_reported_as_unverified_recovery() {
	let (temp, mut params, original) = fixture(&[1., -3.], 2).await;
	params.patch.edits[0].replacement_hex = element(-2.0);
	let root = temp.path().join("state/weight-artifacts-v1");
	tokio::fs::DirBuilder::new()
		.recursive(true)
		.mode(0o700)
		.create(&root)
		.await
		.unwrap();
	// Simulate retained interrupted stages: candidate fits, its reverse does not.
	for index in 0..127 {
		tokio::fs::create_dir(root.join(format!(".pending-fixture-{index}")))
			.await
			.unwrap();
	}
	let rejected = run(&temp, params.clone()).await;
	assert_eq!(rejected["outcome"], "rejected_recovery_unverified");
	assert_eq!(rejected["accepted"], false);
	assert!(rejected["restoration"].is_null());
	assert!(rejected["restoration_error"]
		.as_str()
		.unwrap()
		.contains("count budget exhausted"));
	assert_eq!(tokio::fs::read(&params.patch.path).await.unwrap(), original);
}

#[test]
fn complement_and_bounded_probabilities_are_distinct_from_primary_gain() {
	let constraints = vec![
		Constraint::Complement {
			call: 0,
			put: 1,
			tolerance: 1e-8,
		},
		Constraint::Range {
			column: 0,
			lower: 0.,
			upper: 1.,
		},
	];
	let parent = vec![vec![0.25, 0.75]];
	assert_eq!(
		check_constraints(&constraints, &parent, &parent).unwrap(),
		Vec::<usize>::new()
	);
	assert_eq!(
		check_constraints(&constraints, &[vec![0.75, 0.75]], &parent).unwrap(),
		vec![0]
	);
	assert_eq!(
		check_constraints(&constraints, &[vec![1.25, -0.25]], &parent).unwrap(),
		vec![0, 1]
	);
}
