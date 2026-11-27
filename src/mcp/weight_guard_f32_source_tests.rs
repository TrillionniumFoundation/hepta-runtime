// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact stored-bias and existing durable F32 guard integration controls.

use super::*;
use crate::mcp::weight_guard::Objective;
use crate::mcp::weight_tensor::{ExactElementEdit, PatchTensorParams};

async fn fixture(replacement: f32) -> (tempfile::TempDir, SourceBoundParams, Vec<u8>) {
	let temp = tempfile::tempdir().unwrap();
	let path = temp.path().join("model.safetensors");
	let mut header = serde_json::to_vec(&json!({
		"body.readout.weight":{"dtype":"F32","shape":[2,2],"data_offsets":[0,16]},
		"body.readout.bias":{"dtype":"F32","shape":[2],"data_offsets":[16,24]},
		"physics":{"dtype":"F64","shape":[1],"data_offsets":[24,32]}
	}))
	.unwrap();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
	bytes.extend(header);
	for value in [1_f32, 0.0, 0.0, 1.0, 1.0, -0.0] {
		bytes.extend(value.to_le_bytes());
	}
	bytes.extend(0.25_f64.to_le_bytes());
	tokio::fs::write(&path, &bytes).await.unwrap();
	let bias: Vec<f32> = vec![1.0, -0.0];
	let bias_bytes: Vec<_> = bias.iter().flat_map(|value| value.to_le_bytes()).collect();
	let params = SourceBoundParams {
		guard: GuardedPatchParams {
			patch: PatchTensorParams {
				path: path.to_string_lossy().into(),
				expected_sha256: digest(&bytes),
				tensor_name: "body.readout.weight".into(),
				edits: vec![ExactElementEdit {
					index: 0,
					expected_hex: rea_model::digest_hex(&1_f32.to_le_bytes()),
					replacement_hex: rea_model::digest_hex(&replacement.to_le_bytes()),
				}],
			},
			inputs: vec![vec![1.0, 2.0]],
			bias: Some(bias),
			objective: Objective::SquaredError {
				targets: vec![vec![1.0, 2.0]],
			},
			minimum_gain: 0.0,
			constraints: Vec::new(),
			max_update_l2_norm: Some(2.0),
		},
		bias_binding: BiasBinding {
			tensor_name: "body.readout.bias".into(),
			payload_sha256: digest(&bias_bytes),
		},
	};
	(temp, params, bytes)
}

async fn authenticate(params: &SourceBoundParams) -> Result<BoundGuard> {
	let mut file = tokio::fs::File::open(&params.guard.patch.path).await?;
	authenticate_from_admitted(params, &mut file).await
}

#[tokio::test]
async fn authentic_bias_keeps_original_f32_bits_including_negative_zero() {
	let (_temp, params, _) = fixture(0.0).await;
	let result = authenticate(&params).await.unwrap();
	assert!(result.bias_evidence.caller_bias_matches_stored_bits);
	assert_eq!(
		result.bias_evidence.bias_exact_bytes_hex,
		"0000803f00000080"
	);
	assert_eq!(
		result.guarded_params().bias.as_ref().unwrap()[1].to_bits(),
		(-0_f32).to_bits()
	);
	assert_eq!(
		result.bias_evidence.source_sha256,
		params.guard.patch.expected_sha256
	);
}

#[tokio::test]
async fn wrong_bias_bit_payload_dtype_or_source_is_rejected() {
	let (_temp, original, _) = fixture(0.0).await;
	for kind in 0..5 {
		let mut params = original.clone();
		match kind {
			0 => params.guard.bias.as_mut().unwrap()[0] = 2.0,
			1 => params.guard.bias.as_mut().unwrap()[1] = 0.0,
			2 => params.bias_binding.payload_sha256 = "1".repeat(64),
			3 => params.bias_binding.tensor_name = "physics".into(),
			_ => params.guard.patch.expected_sha256 = "2".repeat(64),
		}
		assert!(authenticate(&params).await.is_err());
	}
}

#[tokio::test]
async fn complete_file_authentication_covers_unchanged_physical_parameters() {
	let (_temp, params, mut bytes) = fixture(0.0).await;
	let last = bytes.len() - 1;
	bytes[last] ^= 1;
	tokio::fs::write(&params.guard.patch.path, bytes)
		.await
		.unwrap();
	assert!(authenticate(&params).await.is_err());
}

#[tokio::test]
async fn bound_f32_uses_existing_guard_for_real_candidate_and_failed_restore() {
	for replacement in [0.0, 2.0] {
		let (temp, params, original) = fixture(replacement).await;
		let state = tempfile::tempdir().unwrap();
		let result = evaluate_with_roots(params.clone(), &[temp.path().into()], state.path())
			.await
			.unwrap();
		assert_eq!(
			result["bias_evidence"]["caller_bias_matches_stored_bits"],
			true
		);
		assert_eq!(result["full_model_executed"], false);
		assert_eq!(result["production_eligible"], false);
		assert_eq!(result["guard"]["accepted"], replacement == 0.0);
		assert_eq!(
			tokio::fs::read(&params.guard.patch.path).await.unwrap(),
			original
		);
		if replacement == 2.0 {
			assert_eq!(result["guard"]["outcome"], "rejected_and_restored");
			let restored = result["guard"]["restoration"]["artifact_path"]
				.as_str()
				.unwrap();
			assert_eq!(tokio::fs::read(restored).await.unwrap(), original);
			let fresh = next_request_with_state(
				&params,
				result["guard"]["restoration"]["artifact_id"]
					.as_str()
					.unwrap(),
				state.path(),
			)
			.await
			.unwrap();
			assert_eq!(fresh["forward"]["outputs"], json!([[2.0, 2.0]]));
			assert_eq!(
				fresh["bias_evidence"]["caller_bias_matches_stored_bits"],
				true
			);
		}
	}
}
