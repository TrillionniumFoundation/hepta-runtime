// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Real-descriptor, F32 operation-order, total-work and complete-pairing controls.

use super::*;
use crate::mcp::weight_tensor::{ExactElementEdit, PatchTensorParams};
use serde_json::json;

fn key(value: &str) -> String {
	sha(value.as_bytes())
}

fn data(rows: usize, columns: usize, parent: &str) -> ChoiceData {
	let rows: Vec<_> = (0..rows)
		.map(|index| {
			let mut row = vec![0.0; columns];
			if index % 2 == 1 {
				row[0] = if (index / 2) % 2 == 0 { 1.0 } else { -1.0 };
			}
			row
		})
		.collect();
	ChoiceData {
		producer: ProducerBinding {
			parent_checkpoint_sha256: parent.into(),
			producer_code_sha256: key("producer"),
			producer_cache_sha256: key("cache"),
			physical_source_sha256: key("physical"),
			evaluation_protocol_sha256: key("protocol"),
		},
		row_ids: (0..rows.len())
			.map(|index| key(&format!("row-{index}")))
			.collect(),
		baseline: vec![0.0; rows.len()],
		pairs: (0..rows.len() / 2)
			.map(|index| QueryPair {
				query_id: key(&format!("query-{index}")),
				choice0_row: 2 * index,
				choice1_row: 2 * index + 1,
				margin_target: if index % 2 == 0 { 1 } else { -1 },
			})
			.collect(),
		rows,
	}
}

fn model(columns: usize, coefficient: f32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
	let length = 2 * columns * 4;
	let mut header = serde_json::to_vec(&json!({
		"body.readout.weight":{"dtype":"F32","shape":[2,columns],"data_offsets":[0,length]},
		"body.readout.bias":{"dtype":"F32","shape":[2],"data_offsets":[length,length+8]},
		"physics":{"dtype":"F64","shape":[1],"data_offsets":[length+8,length+16]}
	}))
	.unwrap();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let mut weights = vec![0_f32; 2 * columns];
	weights[columns] = coefficient;
	let weights: Vec<_> = weights
		.iter()
		.flat_map(|value| value.to_le_bytes())
		.collect();
	let bias: Vec<_> = [0_f32, -0_f32]
		.iter()
		.flat_map(|value| value.to_le_bytes())
		.collect();
	let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
	bytes.extend(header);
	bytes.extend(&weights);
	bytes.extend(&bias);
	bytes.extend(0.25_f64.to_le_bytes());
	(bytes, weights, bias)
}

async fn fixture(rows: usize, columns: usize) -> (tempfile::TempDir, BinaryChoiceParams) {
	let temp = tempfile::tempdir().unwrap();
	let mut binding = Vec::new();
	for (name, coefficient) in [("parent", 0_f32), ("candidate", 1_f32)] {
		let (bytes, weights, bias) = model(columns, coefficient);
		let path = temp.path().join(format!("{name}.safetensors"));
		tokio::fs::write(&path, &bytes).await.unwrap();
		binding.push(CheckpointBinding {
			input: CheckpointInput::Path {
				path: path.to_string_lossy().into(),
			},
			complete_sha256: sha(&bytes),
			weight_payload_sha256: sha(&weights),
			bias_payload_sha256: sha(&bias),
		});
	}
	let data = data(rows, columns, &binding[0].complete_sha256);
	let params = BinaryChoiceParams {
		parent: binding[0].clone(),
		candidate: binding[1].clone(),
		weight_tensor: "body.readout.weight".into(),
		bias_tensor: "body.readout.bias".into(),
		expected_data_sha256: data_sha256(&data).unwrap(),
		data,
	};
	(temp, params)
}

async fn evaluate_at(
	temp: &tempfile::TempDir,
	params: &BinaryChoiceParams,
) -> Result<BinaryChoiceReport> {
	evaluate_with_roots(params, &[temp.path().into()], &temp.path().join("state")).await
}

#[tokio::test]
async fn twenty_columns_and_160_rows_share_three_batches_and_one_total_budget() {
	let (temp, params) = fixture(160, 20).await;
	let report = evaluate_at(&temp, &params).await.unwrap();
	assert_eq!(report.work.combined_linear_macs, 12_800);
	assert_eq!(report.work.combined_linear_output_values, 640);
	assert_eq!(report.work.combined_output_and_aggregate_values, 1120);
	assert_eq!(report.parent.mean_squared_margin_error, 1.0);
	assert_eq!(report.candidate.mean_squared_margin_error, 0.0);
	assert_eq!(report.candidate.accuracy, 1.0);
	assert_eq!(report.parent.accuracy, 0.5);
	assert_eq!(report.mean_squared_error_reduction, 1.0);
	assert_eq!(
		report
			.parent
			.batches
			.iter()
			.map(|batch| batch.row_count)
			.collect::<Vec<_>>(),
		[64, 64, 32]
	);
	assert_eq!(
		report
			.candidate
			.batches
			.iter()
			.map(|batch| batch.row_count)
			.collect::<Vec<_>>(),
		[64, 64, 32]
	);
	assert_eq!(report.candidate.raw_head_bits.len(), 160);
	assert_eq!(report.candidate.query_margin_bits.len(), 80);
	assert!(report.physical_and_bias_bytes_unchanged);
	assert!(!report.full_model_executed);
	assert!(!report.feature_provenance_verified);
	assert!(!report.production_eligible);
	for batch in &report.candidate.batches {
		assert_eq!(batch.source_sha256, params.candidate.complete_sha256);
		assert_eq!(
			batch.captured_weight_payload_sha256,
			params.candidate.weight_payload_sha256
		);
	}
}

#[tokio::test]
async fn exact_64_boundary_and_even_tail_are_not_dropped() {
	for (rows, expected) in [(2, vec![2]), (64, vec![64]), (66, vec![64, 2])] {
		let (temp, params) = fixture(rows, 20).await;
		let report = evaluate_at(&temp, &params).await.unwrap();
		assert_eq!(
			report
				.candidate
				.batches
				.iter()
				.map(|batch| batch.row_count)
				.collect::<Vec<_>>(),
			expected
		);
		assert_eq!(report.candidate.query_margin_bits.len(), rows / 2);
		assert_eq!(report.candidate.mean_squared_margin_error, 0.0);
	}
}

#[test]
fn paired_shape_and_total_budget_reject_odd_tail_and_combined_excess() {
	assert!(work(65, 20).is_err());
	assert!(work(0, 20).is_err());
	assert!(work(2, 0).is_err());
	assert!(work(2, 4097).is_err());
	assert_eq!(
		work(1024, 4096).unwrap().combined_linear_macs,
		weight_forward::MAX_MACS
	);
	assert!(work(1026, 4096).is_err());
	assert!(work(2340, 1).is_ok());
	assert!(work(2342, 1).is_err());
}

#[test]
fn ordered_pairing_targets_unique_ids_and_finite_rows_are_mandatory() {
	let original = data(64, 20, &key("parent"));
	for kind in 0..10 {
		let mut data = original.clone();
		match kind {
			0 => data.pairs[0].choice0_row = 1,
			1 => data.pairs[0].choice1_row = 64,
			2 => data.pairs[1].choice0_row = 0,
			3 => data.pairs[0].margin_target = 0,
			4 => data.pairs[1].query_id = data.pairs[0].query_id.clone(),
			5 => data.row_ids[1] = data.row_ids[0].clone(),
			6 => {
				data.pairs.pop();
			}
			7 => {
				data.baseline.pop();
			}
			8 => data.rows[1][2] = f32::NAN,
			_ => data.baseline[1] = f32::INFINITY,
		}
		assert!(validate_data(&data).is_err(), "case {kind}");
	}
}

#[tokio::test]
async fn data_commitment_includes_baseline_bits_pair_targets_and_producer() {
	let (_temp, original) = fixture(2, 20).await;
	for kind in 0..6 {
		let mut params = original.clone();
		match kind {
			0 => params.data.rows[0][0] = 0.25,
			1 => params.data.baseline[0] = -0.0,
			2 => params.data.pairs[0].margin_target = -1,
			3 => params.data.pairs[0].query_id = key("different-query"),
			4 => params.data.row_ids[0] = key("different-row"),
			_ => params.data.producer.producer_cache_sha256 = key("different-cache"),
		}
		assert_ne!(
			data_sha256(&params.data).unwrap(),
			original.expected_data_sha256
		);
		assert!(validate(&params).is_err());
	}
}

#[test]
fn data_hash_matches_independent_little_endian_protocol_fixture() {
	let fixture = data(2, 1, &key("parent"));
	assert_eq!(
		data_sha256(&fixture).unwrap(),
		"501f2bef395e2571a1beb6db4f96ccbddc431a407f4839ac1720e1c371a74ebb"
	);
}

#[test]
fn f32_subtract_then_add_and_strict_positive_choice_preserve_producer_order() {
	let mut data = data(2, 1, &key("parent"));
	data.baseline = vec![16_777_216.0, 0.0];
	data.pairs[0].margin_target = -1;
	let output = vec![vec![16_777_216.0, -1.0], vec![0.0, 0.0]];
	let (margins, mse, correct) = aggregate(&output, &data).unwrap();
	assert_eq!(margins, vec![0_f32.to_bits()]);
	assert_eq!(mse, 1.0);
	assert_eq!(correct, 1); // Zero selects choice 0; >= would fail this control.
	let wrong_f64 =
		-(f64::from(data.baseline[0]) + f64::from(output[0][1]) - f64::from(output[0][0]));
	assert_eq!(wrong_f64, 1.0);
	assert_ne!(f64::from(f32::from_bits(margins[0])), wrong_f64);
	data.baseline[0] = f32::MAX;
	let overflow = vec![vec![-f32::MAX, f32::MAX], vec![0.0, 0.0]];
	assert!(aggregate(&overflow, &data).is_err());
}

#[tokio::test]
async fn protected_physics_or_bias_changes_reject_even_with_updated_full_hash() {
	for change_bias in [false, true] {
		let (temp, mut params) = fixture(2, 20).await;
		let CheckpointInput::Path { path } = &params.candidate.input else {
			panic!()
		};
		let mut bytes = tokio::fs::read(path).await.unwrap();
		let length = bytes.len();
		if change_bias {
			bytes[length - 12..length - 8].copy_from_slice(&0_f32.to_le_bytes());
			params.candidate.bias_payload_sha256 = sha(&bytes[length - 16..length - 8]);
		} else {
			bytes[length - 1] ^= 1;
		}
		params.candidate.complete_sha256 = sha(&bytes);
		tokio::fs::write(path, bytes).await.unwrap();
		let error = evaluate_at(&temp, &params).await.unwrap_err().to_string();
		assert!(error.contains("every byte outside"), "{error}");
	}
}

#[tokio::test]
async fn wrong_complete_hash_payload_dtype_shape_and_parent_binding_reject() {
	let (temp, original) = fixture(2, 20).await;
	for kind in 0..6 {
		let mut params = original.clone();
		match kind {
			0 => params.candidate.complete_sha256 = key("wrong-file"),
			1 => params.candidate.weight_payload_sha256 = key("wrong-weight"),
			2 => params.candidate.bias_payload_sha256 = key("wrong-bias"),
			3 => params.bias_tensor = "physics".into(),
			4 => params.weight_tensor = "body.readout.bias".into(),
			_ => {
				params.data.producer.parent_checkpoint_sha256 = key("different-parent");
				params.expected_data_sha256 = data_sha256(&params.data).unwrap();
			}
		}
		assert!(evaluate_at(&temp, &params).await.is_err(), "case {kind}");
	}
}

#[tokio::test]
async fn nonfinite_actual_weight_and_expired_shared_deadline_reject() {
	let (temp, mut params) = fixture(2, 20).await;
	let CheckpointInput::Path { path } = &params.candidate.input else {
		panic!()
	};
	let (bytes, weights, _) = model(20, f32::NAN);
	params.candidate.complete_sha256 = sha(&bytes);
	params.candidate.weight_payload_sha256 = sha(&weights);
	tokio::fs::write(path, bytes).await.unwrap();
	assert!(evaluate_at(&temp, &params)
		.await
		.unwrap_err()
		.to_string()
		.contains("nonfinite"));
	let mut file = open(
		&params.parent,
		&[temp.path().into()],
		&temp.path().join("state"),
	)
	.await
	.unwrap();
	assert!(
		source::capture(&params, &params.parent, &mut file, 20, Instant::now())
			.await
			.is_err()
	);
}

#[test]
fn bounded_request_writer_rejects_overflow_instead_of_truncating() {
	let mut writer = BoundedHash {
		count: MAX_REQUEST_BYTES - 1,
		hash: Sha256::new(),
	};
	assert_eq!(writer.write(&[1]).unwrap(), 1);
	assert!(writer.write(&[2]).is_err());
	assert_eq!(writer.count, MAX_REQUEST_BYTES);
}

#[tokio::test]
async fn actual_owner_artifact_and_new_restored_request_keep_source_identity() {
	let (temp, mut params) = fixture(66, 20).await;
	let CheckpointInput::Path { path } = &params.parent.input else {
		panic!()
	};
	let state = temp.path().join("state");
	let receipt = weight_artifact::apply_with_roots(
		PatchTensorParams {
			path: path.clone(),
			expected_sha256: params.parent.complete_sha256.clone(),
			tensor_name: params.weight_tensor.clone(),
			edits: vec![ExactElementEdit {
				index: 20,
				expected_hex: rea_model::digest_hex(&0_f32.to_le_bytes()),
				replacement_hex: rea_model::digest_hex(&1_f32.to_le_bytes()),
			}],
		},
		&[temp.path().into()],
		&state,
		None,
		None,
	)
	.await
	.unwrap();
	assert_eq!(receipt["sha256"], params.candidate.complete_sha256);
	let id = receipt["artifact_id"].as_str().unwrap();
	params.candidate.input = CheckpointInput::Artifact {
		artifact_id: id.into(),
	};
	let edited = evaluate_at(&temp, &params).await.unwrap();
	assert_eq!(edited.candidate.mean_squared_margin_error, 0.0);
	let restored = weight_artifact::restore_with_state(id, &state)
		.await
		.unwrap();
	params.candidate = params.parent.clone();
	params.candidate.input = CheckpointInput::Artifact {
		artifact_id: restored["artifact_id"].as_str().unwrap().into(),
	};
	let fresh = evaluate_at(&temp, &params).await.unwrap();
	assert_eq!(fresh.parent.raw_head_bits, fresh.candidate.raw_head_bits);
	assert_eq!(fresh.mean_squared_error_reduction, 0.0);
	assert_eq!(
		fresh.candidate.source.complete_sha256,
		params.parent.complete_sha256
	);
	params.candidate.complete_sha256 = key("wrong-owner-source");
	assert!(evaluate_at(&temp, &params)
		.await
		.unwrap_err()
		.to_string()
		.contains("canonical owner manifest"));
}
