// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Actual cohort publication, descriptor re-open, inverse publication and fresh-request controls.

use super::*;
use crate::mcp::weight_f16_proposal::{F16ProposalParams, Member, ReadSetRole, TensorBinding};
use crate::mcp::weight_guard::{Constraint, Objective};
use crate::mcp::weight_tensor::ExactElementEdit;
use f16::{FeatureBatch, FeatureOrigin, HeadSelection};

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn key(value: u8) -> String {
	hex(&[value; 32])
}

fn row_hash(features: &FeatureBatch) -> String {
	let mut bytes = b"hepta.weight.coupled-f16-feature-rows.v1\0".to_vec();
	bytes.extend((features.rows.len() as u64).to_le_bytes());
	bytes.extend((features.rows[0].len() as u64).to_le_bytes());
	for (index, row) in features.rows.iter().enumerate() {
		bytes.extend([index as u8; 32]);
		for value in row {
			bytes.extend(value.to_le_bytes());
		}
	}
	super::super::digest(&bytes)
}

async fn fixture(
	weight_replacement: u16,
	bias_replacement: u16,
) -> (tempfile::TempDir, CoupledF16EvaluationParams, Vec<u8>) {
	let temp = tempfile::tempdir().unwrap();
	let path = temp.path().join("source.safetensors");
	let weights = [0x00, 0x3c, 0x00, 0x00]; // [1, 0]
	let bias = [0x00, 0x38]; // [0.5]
	let mut header = serde_json::to_vec(&json!({
		"head.weight":{"dtype":"F16","shape":[1,2],"data_offsets":[0,4]},
		"head.bias":{"dtype":"F16","shape":[1],"data_offsets":[4,6]},
		"protected":{"dtype":"F64","shape":[1],"data_offsets":[6,14]}
	}))
	.unwrap();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
	bytes.extend(header);
	bytes.extend(weights);
	bytes.extend(bias);
	bytes.extend((-0.0_f64).to_le_bytes());
	tokio::fs::write(&path, &bytes).await.unwrap();
	let source_sha = super::super::digest(&bytes);
	let member = |name: &str, shape: Vec<u64>, original: &[u8], replacement: u16| Member {
		binding: TensorBinding {
			name: name.into(),
			dtype: "F16".into(),
			shape,
			payload_sha256: super::super::digest(original),
		},
		role: ReadSetRole::EditTarget,
		edits: vec![ExactElementEdit {
			index: 0,
			expected_hex: hex(&original[..2]),
			replacement_hex: hex(&replacement.to_le_bytes()),
		}],
		maximum_update_l2_norm: 4.0,
	};
	let mut features = FeatureBatch {
		origin: FeatureOrigin::SyntheticControl,
		source_checkpoint_sha256: source_sha.clone(),
		source_domain_sha256: key(2),
		producer_code_sha256: key(3),
		producer_configuration_sha256: key(4),
		declared_producer_receipt_sha256: key(5),
		data_manifest_sha256: key(6),
		sample_ids: vec![key(0), key(1)],
		expected_rows_sha256: String::new(),
		rows: vec![vec![1.0, 0.0], vec![0.0, 1.0]],
	};
	features.expected_rows_sha256 = row_hash(&features);
	let params = CoupledF16EvaluationParams {
		proposal: F16ProposalParams {
			request_id: key(11),
			path: path.to_string_lossy().into(),
			source_sha256: source_sha,
			members: vec![
				member("head.weight", vec![1, 2], &weights, weight_replacement),
				member("head.bias", vec![1], &bias, bias_replacement),
			],
			maximum_update_l2_norm: 6.0,
			data_manifest_sha256: key(6),
			objective_sha256: key(7),
			dependency_manifest_sha256: key(8),
		},
		head: HeadSelection {
			weight_name: "head.weight".into(),
			bias_name: "head.bias".into(),
		},
		features,
		objective: Objective::SquaredError {
			targets: vec![vec![3.0], vec![1.0]],
		},
		constraints: Vec::new(),
		minimum_gain: 0.0,
	};
	(temp, params, bytes)
}

async fn run_fixture(
	temp: &tempfile::TempDir,
	params: CoupledF16EvaluationParams,
) -> Result<ResearchReport> {
	run_with_roots(params, &[temp.path().into()], &temp.path().join("state")).await
}

async fn artifact_count(temp: &tempfile::TempDir) -> usize {
	let Ok(mut directory) =
		tokio::fs::read_dir(temp.path().join("state/weight-artifacts-v1")).await
	else {
		return 0;
	};
	let mut count = 0;
	while let Some(entry) = directory.next_entry().await.unwrap() {
		count += usize::from(super::super::valid_id(&entry.file_name().to_string_lossy()));
	}
	count
}

#[tokio::test]
async fn positive_candidate_uses_actual_published_bytes_and_is_restored() {
	let (temp, params, original) = fixture(0x4000, 0x3c00).await; // W=2, b=1
	let result = run_fixture(&temp, params.clone()).await.unwrap();
	let value = serde_json::to_value(&result).unwrap();
	assert_eq!(value["outcome"], "supplied_row_pass_and_restored");
	assert_eq!(
		value["candidate_readback"]["outputs"],
		json!([[3.0], [1.0]])
	);
	assert_eq!(value["restored_readback"]["outputs"], json!([[1.5], [0.5]]));
	assert_eq!(value["restored_bytes_and_predictions_verified"], true);
	assert_eq!(value["production_eligible"], false);
	assert_eq!(value["crash_recovery_verified"], false);
	assert_eq!(value["full_model_executed"], false);
	assert_eq!(artifact_count(&temp).await, 2);
	assert_eq!(
		tokio::fs::read(&params.proposal.path).await.unwrap(),
		original
	);
	let restored = value["restoration"]["artifact_path"].as_str().unwrap();
	assert_eq!(tokio::fs::read(restored).await.unwrap(), original);
	let fresh = next_request_with_state(
		&params,
		value["restoration"]["artifact_id"].as_str().unwrap(),
		&temp.path().join("state"),
	)
	.await
	.unwrap();
	assert_eq!(
		fresh.prediction_bits_sha256(),
		result
			.restored_readback
			.as_ref()
			.unwrap()
			.prediction_bits_sha256()
	);
	assert!(next_request_with_state(
		&params,
		value["publication"]["artifact_id"].as_str().unwrap(),
		&temp.path().join("state"),
	)
	.await
	.is_err());
}

#[tokio::test]
async fn wrong_direction_and_preservation_violation_are_both_restored() {
	for preserve in [false, true] {
		let (temp, mut params, original) = if preserve {
			fixture(0x4000, 0x3c00).await
		} else {
			fixture(0x0000, 0x0000).await
		};
		if preserve {
			params.constraints.push(Constraint::Preserve {
				column: 0,
				max_absolute_change: 0.0,
			});
		}
		let report = run_fixture(&temp, params.clone()).await.unwrap();
		assert_eq!(report.outcome, "supplied_row_reject_and_restored");
		assert!(!report.supplied_row_condition_satisfied);
		assert!(report.restored_bytes_and_predictions_verified);
		assert!(report.restore_attempted);
		assert_eq!(artifact_count(&temp).await, 2);
		assert_eq!(
			tokio::fs::read(&params.proposal.path).await.unwrap(),
			original
		);
	}
}

#[tokio::test]
async fn keep_authenticates_source_and_does_not_publish() {
	let (temp, params, _) = fixture(0x3c00, 0x3800).await;
	let report = run_fixture(&temp, params.clone()).await.unwrap();
	assert_eq!(report.outcome, "keep_without_publication");
	assert!(!report.canonical_owner_invoked);
	assert!(!report.restore_attempted);
	assert_eq!(artifact_count(&temp).await, 0);
	tokio::fs::write(&params.proposal.path, b"different source")
		.await
		.unwrap();
	assert!(run_fixture(&temp, params).await.is_err());
	assert_eq!(artifact_count(&temp).await, 0);
}

#[tokio::test]
async fn fixed_request_repeats_same_artifacts_but_changed_objective_is_rejected() {
	let (temp, mut params, _) = fixture(0x4000, 0x3c00).await;
	let first = run_fixture(&temp, params.clone()).await.unwrap();
	let repeated = run_fixture(&temp, params.clone()).await.unwrap();
	assert_eq!(
		first.publication.as_ref().unwrap()["artifact_id"],
		repeated.publication.as_ref().unwrap()["artifact_id"]
	);
	assert_eq!(
		first.restoration.as_ref().unwrap()["artifact_id"],
		repeated.restoration.as_ref().unwrap()["artifact_id"]
	);
	assert_eq!(artifact_count(&temp).await, 2);
	params.minimum_gain = 100.0;
	assert!(run_fixture(&temp, params).await.is_err());
	assert_eq!(artifact_count(&temp).await, 2);
}

#[tokio::test]
async fn reopened_typed_plan_rejects_modified_features_and_candidate_bytes() {
	let (temp, params, _) = fixture(0x4000, 0x3c00).await;
	let report = run_fixture(&temp, params.clone()).await.unwrap();
	let candidate = report.publication.as_ref().unwrap();
	let id = artifact_id(candidate).unwrap();
	let state = temp.path().join("state");
	let mut changed = params.clone();
	changed.minimum_gain = 1.0;
	assert!(
		verify_artifact(&report.preflight, &changed, id, &state, Version::Candidate)
			.await
			.is_err()
	);
	let path = candidate["artifact_path"].as_str().unwrap();
	let mut bytes = tokio::fs::read(path).await.unwrap();
	let last = bytes.len() - 1;
	bytes[last] ^= 1; // A protected F64 byte, outside selected head parameters.
	tokio::fs::write(path, bytes).await.unwrap();
	assert!(
		verify_artifact(&report.preflight, &params, id, &state, Version::Candidate)
			.await
			.is_err()
	);
}

#[tokio::test]
async fn malformed_exact_bytes_fail_before_any_owner_publication() {
	let (temp, mut params, _) = fixture(0x4000, 0x3c00).await;
	params.proposal.members[0].edits[0].expected_hex = "0000".into();
	assert!(run_fixture(&temp, params).await.is_err());
	assert_eq!(artifact_count(&temp).await, 0);
}
