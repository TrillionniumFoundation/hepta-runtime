// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Synthetic coefficient and source-binding controls; no model or owner runs.

use super::*;
use serde_json::{json, Value};

fn pack(header: &[u8], payload: &[u8]) -> Vec<u8> {
	let mut result = (header.len() as u64).to_le_bytes().to_vec();
	result.extend_from_slice(header);
	result.extend_from_slice(payload);
	result
}

fn f32_bytes(values: &[f32]) -> Vec<u8> {
	values
		.iter()
		.flat_map(|value| value.to_le_bytes())
		.collect()
}

fn fixture(
	weights: &[f32],
	outputs: usize,
	inputs: usize,
	bias: &[f32],
	bias_first: bool,
) -> (AffineParams, Vec<u8>) {
	assert_eq!(weights.len(), outputs * inputs);
	assert_eq!(bias.len(), outputs);
	let wb = f32_bytes(weights);
	let bb = f32_bytes(bias);
	let (wo, bo) = if bias_first {
		(bb.len(), 0)
	} else {
		(0, wb.len())
	};
	let header = serde_json::to_vec(&json!({
		"weights": {"dtype":"F32", "shape":[outputs,inputs], "data_offsets":[wo,wo+wb.len()]},
		"bias": {"dtype":"F32", "shape":[outputs], "data_offsets":[bo,bo+bb.len()]},
		"__metadata__": {"kind":"synthetic compiler fixture"}
	}))
	.unwrap();
	let payload = if bias_first {
		[bb.as_slice(), wb.as_slice()].concat()
	} else {
		[wb.as_slice(), bb.as_slice()].concat()
	};
	let bytes = pack(&header, &payload);
	let params = AffineParams {
		request_id: "1".repeat(64),
		path: if cfg!(windows) {
			r"C:\not-opened\affine-fixture.safetensors".into()
		} else {
			"/not-opened/affine-fixture.safetensors".into()
		},
		source_sha256: sha(&bytes),
		weights: TensorBinding {
			name: "weights".into(),
			dtype: "F32".into(),
			shape: vec![outputs as u64, inputs as u64],
			sha256: sha(&wb),
		},
		bias: TensorBinding {
			name: "bias".into(),
			dtype: "F32".into(),
			shape: vec![outputs as u64],
			sha256: sha(&bb),
		},
		transform: AffineTransform {
			matrix: (0..inputs)
				.map(|row| {
					(0..inputs)
						.map(|column| if row == column { 1. } else { 0. })
						.collect()
				})
				.collect(),
			offset: vec![0.; inputs],
			old_mean: vec![0.; inputs],
			new_mean: vec![0.; inputs],
			old_scale: vec![1.; inputs],
			new_scale: vec![1.; inputs],
		},
		weights_maximum_update_l2_norm: 100.,
		bias_maximum_update_l2_norm: 100.,
		maximum_update_l2_norm: 100.,
		data_manifest_sha256: "2".repeat(64),
		objective_sha256: "3".repeat(64),
		dependency_manifest_sha256: "4".repeat(64),
	};
	(params, bytes)
}

fn header_end(bytes: &[u8]) -> usize {
	8 + u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize
}

fn with_header(
	params: &AffineParams,
	bytes: &[u8],
	change: impl FnOnce(&mut Value),
) -> (AffineParams, Vec<u8>) {
	let end = header_end(bytes);
	let mut header: Value = serde_json::from_slice(&bytes[8..end]).unwrap();
	change(&mut header);
	with_header_bytes(params, bytes, &serde_json::to_vec(&header).unwrap())
}

fn with_header_bytes(
	params: &AffineParams,
	bytes: &[u8],
	header: &[u8],
) -> (AffineParams, Vec<u8>) {
	let changed = pack(header, &bytes[header_end(bytes)..]);
	let mut params = params.clone();
	params.source_sha256 = sha(&changed);
	(params, changed)
}

/// Materialize only this small test fixture, checking the existing exact edit contract.
fn materialize(params: &AffineParams, bytes: &[u8], proposal: &AffineProposal) -> Vec<u8> {
	let pair = source::authenticate(params, bytes).unwrap();
	let mut result = bytes.to_vec();
	for member in &proposal.cohort_proposal().unwrap().members {
		let tensor = if member.tensor_name == params.weights.name {
			&pair.weights
		} else {
			assert_eq!(member.tensor_name, params.bias.name);
			&pair.bias
		};
		for edit in &member.edits {
			let offset = tensor.file_offset + edit.index as usize * 4;
			assert_eq!(hex(&bytes[offset..offset + 4]), edit.expected_hex);
			let after = crate::mcp::weight_tensor::unhex(&edit.replacement_hex).unwrap();
			assert_eq!(after.len(), 4);
			result[offset..offset + 4].copy_from_slice(&after);
		}
	}
	assert_eq!(sha(&result), proposal.candidate_sha256);
	result
}

fn dyadic_params(bias_first: bool) -> (AffineParams, Vec<u8>) {
	let (mut params, bytes) = fixture(&[2., -4., 1., 3.], 2, 2, &[0.5, -2.], bias_first);
	params.transform = AffineTransform {
		matrix: vec![vec![1., 0.5], vec![-1., 2.]],
		offset: vec![0.5, -0.5],
		old_mean: vec![1., -1.],
		new_mean: vec![2., 1.],
		old_scale: vec![2., 4.],
		new_scale: vec![4., 2.],
	};
	(params, bytes)
}

#[test]
fn affine_identity_preserves_signed_zero_and_extreme_source_bits() {
	let (mut params, bytes) = fixture(&[f32::MAX, -0., f32::from_bits(1)], 1, 3, &[-0.], true);
	params.transform.old_scale.fill(f64::from_bits(1));
	params
		.transform
		.new_scale
		.clone_from(&params.transform.old_scale);
	params.transform.old_mean.fill(f64::MAX);
	params
		.transform
		.new_mean
		.clone_from(&params.transform.old_mean);
	params.weights_maximum_update_l2_norm = 0.;
	params.bias_maximum_update_l2_norm = 0.;
	params.maximum_update_l2_norm = 0.;
	let original = bytes.clone();
	let proposal = compile(&params, &bytes).unwrap();
	assert!(proposal.is_keep());
	assert!(proposal.explicit_identity);
	assert!(proposal.rounding.is_none());
	assert_eq!(proposal.source_sha256, proposal.candidate_sha256);
	assert_eq!(proposal.global_budget.elements_checked, 4);
	assert_eq!(bytes, original);
	assert!(proposal.cohort_proposal().is_none());
}

#[test]
fn affine_identity_still_validates_source_finite_values_and_budgets() {
	let (params, bytes) = fixture(&[1.], 1, 1, &[0.], false);
	let mut bad = params.clone();
	bad.source_sha256 = "f".repeat(64);
	assert!(compile(&bad, &bytes).is_err());
	let mut bad = params.clone();
	bad.bias.sha256 = "f".repeat(64);
	assert!(compile(&bad, &bytes).is_err());
	let mut bad = params.clone();
	bad.maximum_update_l2_norm = -1.;
	assert!(compile(&bad, &bytes).is_err());
	let (params, bytes) = fixture(&[f32::NAN], 1, 1, &[0.], false);
	assert!(compile(&params, &bytes).is_err());
	let (params, bytes) = fixture(&[1.], 1, 1, &[f32::NEG_INFINITY], false);
	assert!(compile(&params, &bytes).is_err());
}

#[test]
fn affine_dyadic_coupled_coefficients_match_independent_bits_and_inverse() {
	// Hand-derived values: W=[8,-3;-1,3.5], b=[2,-0.625]. No compiler oracle.
	let expected_weights = [0x41000000_u32, 0xc0400000, 0xbf800000, 0x40600000];
	let expected_bias = [0x40000000_u32, 0xbf200000];
	for bias_first in [false, true] {
		let (params, bytes) = dyadic_params(bias_first);
		let original = bytes.clone();
		let proposal = compile(&params, &bytes).unwrap();
		assert!(!proposal.is_keep());
		assert!(!proposal.explicit_identity);
		assert_eq!(proposal.rounding.as_ref().unwrap().coefficients_rounded, 0);
		assert_eq!(proposal.rounding.as_ref().unwrap().coefficients_lowered, 6);
		let request = proposal.cohort_proposal().unwrap();
		assert_eq!(request.members.len(), 2);
		assert!(matches!(
			&request.training,
			cohort::TrainingContract::InferenceOnly
		));
		let candidate = materialize(&params, &bytes, &proposal);
		let pair = source::authenticate(&params, &bytes).unwrap();
		for (tensor, expected) in [
			(&pair.weights, expected_weights.as_slice()),
			(&pair.bias, expected_bias.as_slice()),
		] {
			let expected_bytes: Vec<_> = expected
				.iter()
				.flat_map(|bits| bits.to_le_bytes())
				.collect();
			assert_eq!(
				&candidate[tensor.file_offset..tensor.file_offset + tensor.bytes.len()],
				expected_bytes
			);
		}
		assert_eq!(
			&candidate[..header_end(&bytes)],
			&bytes[..header_end(&bytes)]
		);
		let mut reversed = candidate;
		for tensor in [&pair.weights, &pair.bias] {
			reversed[tensor.file_offset..tensor.file_offset + tensor.bytes.len()]
				.copy_from_slice(tensor.bytes);
		}
		assert_eq!(reversed, original);
		assert_eq!(bytes, original);
		assert!(!proposal.external_relation_verified);
		assert!(!proposal.encoded_forward_equivalence_verified);
		assert!(!proposal.behavior_evaluated);
		assert!(!proposal.production_eligible);
	}
}

#[test]
fn affine_singular_relation_is_allowed_and_unchanged_bias_stays_in_read_set() {
	let (mut params, bytes) = fixture(&[2., 3.], 1, 2, &[4.], false);
	params.transform.matrix = vec![vec![1., 1.], vec![0., 0.]];
	let proposal = compile(&params, &bytes).unwrap();
	let request = proposal.cohort_proposal().unwrap();
	assert_eq!(request.members.len(), 1);
	assert_eq!(request.members[0].tensor_name, "weights");
	assert_eq!(proposal.bias.sha256, params.bias.sha256);
	let candidate = materialize(&params, &bytes, &proposal);
	let pair = source::authenticate(&params, &bytes).unwrap();
	assert_eq!(
		&candidate[pair.weights.file_offset..pair.weights.file_offset + 8],
		f32_bytes(&[2., 2.])
	);
	assert_eq!(&candidate[pair.bias.file_offset..], pair.bias.bytes);
	assert!(!proposal.external_relation_verified);
}

#[test]
fn affine_bias_shift_uses_original_weight_and_preserves_unedited_weight_binding() {
	let (mut params, bytes) = fixture(&[2.], 1, 1, &[3.], false);
	params.transform.offset[0] = 0.5;
	params.weights_maximum_update_l2_norm = 0.;
	let proposal = compile(&params, &bytes).unwrap();
	assert_eq!(proposal.weights.sha256, params.weights.sha256);
	let members = &proposal.cohort_proposal().unwrap().members;
	assert_eq!(members.len(), 1);
	assert_eq!(members[0].tensor_name, "bias");
	assert_eq!(members[0].edits[0].replacement_hex, "00008040");
}

#[test]
fn affine_known_cast_rounding_and_underflow_are_observations() {
	let (mut params, bytes) = fixture(&[1.], 1, 1, &[0.], false);
	params.transform.old_scale[0] = 3.;
	let proposal = compile(&params, &bytes).unwrap();
	let rounding = proposal.rounding.as_ref().unwrap();
	assert_eq!(rounding.coefficients_rounded, 1);
	assert_eq!(rounding.nonzero_underflowed_to_zero, 0);
	assert!(rounding.maximum_absolute_cast_difference > 0.);
	assert_eq!(
		proposal.cohort_proposal().unwrap().members[0].edits[0].replacement_hex,
		"abaaaa3e"
	);
	assert!(!proposal.encoded_forward_equivalence_verified);
	let (mut params, bytes) = fixture(&[f32::from_bits(1)], 1, 1, &[0.], false);
	params.transform.old_scale[0] = 4.;
	let proposal = compile(&params, &bytes).unwrap();
	assert_eq!(
		proposal
			.rounding
			.as_ref()
			.unwrap()
			.nonzero_underflowed_to_zero,
		1
	);
	assert_eq!(
		proposal.cohort_proposal().unwrap().members[0].edits[0].replacement_hex,
		"00000000"
	);
}

#[test]
fn affine_member_and_joint_norm_limits_reject_independently() {
	let (mut params, bytes) = fixture(&[1.], 1, 1, &[0.], false);
	params.transform.new_scale[0] = 2.;
	params.transform.offset[0] = 1.;
	params.weights_maximum_update_l2_norm = 1.;
	params.bias_maximum_update_l2_norm = 1.;
	params.maximum_update_l2_norm = 2.;
	assert!(compile(&params, &bytes).is_ok());
	let mut bad = params.clone();
	bad.weights_maximum_update_l2_norm = 0.5;
	assert!(compile(&bad, &bytes).is_err());
	let mut bad = params.clone();
	bad.bias_maximum_update_l2_norm = 0.5;
	assert!(compile(&bad, &bytes).is_err());
	let mut bad = params.clone();
	bad.maximum_update_l2_norm = 1.;
	assert!(compile(&bad, &bytes).is_err());
}

#[test]
fn affine_rejects_invalid_request_bindings_and_shapes() {
	let (params, bytes) = fixture(&[1., 2.], 1, 2, &[3.], false);
	let changes: [fn(&mut AffineParams); 13] = [
		|p| p.source_sha256 = "F".repeat(64),
		|p| p.request_id.clear(),
		|p| p.dependency_manifest_sha256.clear(),
		|p| p.path = "relative".into(),
		|p| p.path = "/tmp/../candidate".into(),
		|p| p.path.push('\0'),
		|p| p.weights.name = p.bias.name.clone(),
		|p| p.bias.name = "missing".into(),
		|p| p.weights.shape.swap(0, 1),
		|p| p.bias.shape = vec![1, 1],
		|p| p.bias.shape = vec![2],
		|p| {
			p.transform.matrix[0].pop();
		},
		|p| p.transform.new_mean.clear(),
	];
	for (index, change) in changes.into_iter().enumerate() {
		let mut bad = params.clone();
		change(&mut bad);
		assert!(compile(&bad, &bytes).is_err(), "request control {index}");
	}
	for dtype in ["F16", "BF16", "F64", "I32"] {
		let mut bad = params.clone();
		bad.weights.dtype = dtype.into();
		assert!(compile(&bad, &bytes).is_err());
	}
}

#[test]
fn affine_rejects_nonfinite_transform_values_and_nonpositive_scales() {
	let (params, bytes) = fixture(&[1.], 1, 1, &[0.], false);
	for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
		for field in 0..6 {
			let mut bad = params.clone();
			match field {
				0 => bad.transform.matrix[0][0] = value,
				1 => bad.transform.offset[0] = value,
				2 => bad.transform.old_mean[0] = value,
				3 => bad.transform.new_mean[0] = value,
				4 => bad.transform.old_scale[0] = value,
				_ => bad.transform.new_scale[0] = value,
			}
			assert!(compile(&bad, &bytes).is_err());
		}
	}
	for value in [0., -0., -1.] {
		let mut bad = params.clone();
		bad.transform.old_scale[0] = value;
		assert!(compile(&bad, &bytes).is_err());
		let mut bad = params.clone();
		bad.transform.new_scale[0] = value;
		assert!(compile(&bad, &bytes).is_err());
	}
}

#[test]
fn affine_rejects_intermediate_and_encoded_overflow() {
	let (params, bytes) = fixture(&[f32::MAX], 1, 1, &[0.], false);
	let mut bad = params.clone();
	bad.transform.old_scale[0] = f64::from_bits(1);
	assert!(compile(&bad, &bytes).is_err());
	let mut bad = params.clone();
	bad.transform.matrix[0][0] = f64::MAX;
	bad.transform.new_mean[0] = 2.;
	assert!(compile(&bad, &bytes).is_err());
	let mut bad = params.clone();
	bad.transform.new_scale[0] = 2.;
	assert!(compile(&bad, &bytes).is_err());
}

#[test]
fn affine_rejects_changed_source_and_stale_target_payload_hash() {
	let (params, mut bytes) = fixture(&[1.], 1, 1, &[0.], false);
	let start = header_end(&bytes);
	bytes[start..start + 4].copy_from_slice(&2_f32.to_le_bytes());
	assert!(compile(&params, &bytes).is_err());
	let mut params = params;
	params.source_sha256 = sha(&bytes);
	assert!(compile(&params, &bytes).is_err());
}

#[test]
fn affine_rejects_header_duplicates_unknown_fields_and_invalid_extents() {
	let (params, bytes) = fixture(&[1.], 1, 1, &[2.], false);
	let original: Value = serde_json::from_slice(&bytes[8..header_end(&bytes)]).unwrap();
	let w = serde_json::to_string(&original["weights"]).unwrap();
	let b = serde_json::to_string(&original["bias"]).unwrap();
	for header in [
		format!("{{\"weights\":{w},\"weights\":{w},\"bias\":{b}}}"),
		format!("{{\"weights\":{{\"dtype\":\"F32\",\"dtype\":\"F32\",\"shape\":[1,1],\"data_offsets\":[0,4]}},\"bias\":{b}}}"),
	] {
		let (p, raw) = with_header_bytes(&params, &bytes, header.as_bytes());
		assert!(compile(&p, &raw).is_err());
	}
	let changes: [fn(&mut Value); 7] = [
		|h| h["weights"]["unexpected"] = json!(true),
		|h| h["weights"]["data_offsets"] = json!([0, 8]),
		|h| h["bias"]["data_offsets"] = json!([0, 4]),
		|h| h["bias"]["data_offsets"] = json!([5, 9]),
		|h| h["weights"]["data_offsets"] = json!([u64::MAX, u64::MAX]),
		|h| h["weights"]["dtype"] = json!("UNKNOWN"),
		|h| h["__metadata__"] = json!({"value":1}),
	];
	for (index, change) in changes.into_iter().enumerate() {
		let (p, raw) = with_header(&params, &bytes, change);
		assert!(compile(&p, &raw).is_err(), "directory control {index}");
	}
	let mut truncated = bytes.clone();
	truncated.pop();
	let mut p = params.clone();
	p.source_sha256 = sha(&truncated);
	assert!(compile(&p, &truncated).is_err());
	let mut trailing = bytes;
	trailing.push(0);
	let mut p = params;
	p.source_sha256 = sha(&trailing);
	assert!(compile(&p, &trailing).is_err());
}

#[test]
fn affine_exact_element_cap_and_header_limit_are_enforced() {
	let (params, bytes) = fixture(&vec![0.; 32 * 31], 32, 31, &[0.; 32], false);
	let proposal = compile(&params, &bytes).unwrap();
	assert!(proposal.is_keep());
	assert_eq!(proposal.global_budget.elements_checked, 1024);
	let (params, bytes) = fixture(&vec![0.; 32 * 32], 32, 32, &[0.; 32], false);
	assert!(compile(&params, &bytes).is_err());
	let mut oversized_header = (256 * 1024 + 1_u64).to_le_bytes().to_vec();
	oversized_header.push(b'{');
	let (params, _) = fixture(&[1.], 1, 1, &[0.], false);
	assert!(compile(&params, &oversized_header).is_err());
	assert!(compile(&params, &[0_u8; 8]).is_err());
}

#[test]
fn affine_claim_and_coefficient_changes_are_committed_without_truth_claims() {
	let (params, bytes) = dyadic_params(false);
	let a = compile(&params, &bytes).unwrap();
	let mut changed = params.clone();
	changed.objective_sha256 = "a".repeat(64);
	let b = compile(&changed, &bytes).unwrap();
	assert_eq!(a.candidate_sha256, b.candidate_sha256);
	assert_ne!(a.request_sha256, b.request_sha256);
	assert_ne!(
		a.cohort_proposal()
			.unwrap()
			.identity
			.dependency_manifest_sha256,
		b.cohort_proposal()
			.unwrap()
			.identity
			.dependency_manifest_sha256
	);
	changed.transform.offset[0] += 1.;
	let c = compile(&changed, &bytes).unwrap();
	assert_ne!(b.transform_sha256, c.transform_sha256);
	assert_ne!(b.candidate_sha256, c.candidate_sha256);
	let record = serde_json::to_value(c).unwrap();
	for field in [
		"external_relation_verified",
		"encoded_forward_equivalence_verified",
		"behavior_evaluated",
		"production_eligible",
	] {
		assert_eq!(record[field], false);
	}
	let mut invalid = serde_json::to_value(params).unwrap();
	invalid["implicit_permission"] = json!(true);
	assert!(serde_json::from_value::<AffineParams>(invalid).is_err());
}
