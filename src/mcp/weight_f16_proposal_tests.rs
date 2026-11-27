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

//! Authored synthetic descriptor/byte controls. No model or artifact owner runs.

use super::*;
use serde_json::{json, Value};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

const HEADER_BYTES: usize = 4096;
const PREFIX_BYTES: usize = 8 + HEADER_BYTES;

struct Fixture {
	params: F16ProposalParams,
	bytes: Vec<u8>,
	weight_offset: usize,
	bias_offset: usize,
}

fn bits(values: &[u16]) -> Vec<u8> {
	values
		.iter()
		.flat_map(|value| value.to_le_bytes())
		.collect()
}

fn pack(header: &Value, payload: &[u8]) -> Vec<u8> {
	let mut header = serde_json::to_vec(header).unwrap();
	assert!(header.len() <= HEADER_BYTES);
	header.resize(HEADER_BYTES, b' ');
	let mut bytes = (HEADER_BYTES as u64).to_le_bytes().to_vec();
	bytes.extend(header);
	bytes.extend_from_slice(payload);
	bytes
}

fn fixture(weights: &[u16], bias: &[u16], padding: usize) -> Fixture {
	assert!(!weights.is_empty() && !bias.is_empty());
	let weights = bits(weights);
	let bias = bits(bias);
	let header = json!({
		"padding":{"dtype":"U8","shape":[padding],"data_offsets":[0,padding]},
		"weights":{"dtype":"F16","shape":[1,weights.len()/2],"data_offsets":[padding,padding+weights.len()]},
		"bias":{"dtype":"F16","shape":[bias.len()/2],"data_offsets":[padding+weights.len(),padding+weights.len()+bias.len()]},
		"__metadata__":{"fixture":"F16 exact byte proposal"}
	});
	let mut payload = vec![0_u8; padding];
	payload.extend_from_slice(&weights);
	payload.extend_from_slice(&bias);
	let bytes = pack(&header, &payload);
	let params = F16ProposalParams {
		request_id: "1".repeat(64),
		path: "/not-opened/f16-proposal-fixture.safetensors".into(),
		source_sha256: sha(&bytes),
		members: vec![
			Member {
				binding: TensorBinding {
					name: "weights".into(),
					dtype: "F16".into(),
					shape: vec![1, (weights.len() / 2) as u64],
					payload_sha256: sha(&weights),
				},
				role: ReadSetRole::EditTarget,
				edits: vec![ExactElementEdit {
					index: 0,
					expected_hex: hex(&weights[..2]),
					replacement_hex: hex(&0x4000_u16.to_le_bytes()),
				}],
				maximum_update_l2_norm: 100.,
			},
			Member {
				binding: TensorBinding {
					name: "bias".into(),
					dtype: "F16".into(),
					shape: vec![(bias.len() / 2) as u64],
					payload_sha256: sha(&bias),
				},
				role: ReadSetRole::Dependency,
				edits: Vec::new(),
				maximum_update_l2_norm: 0.,
			},
		],
		maximum_update_l2_norm: 100.,
		data_manifest_sha256: "2".repeat(64),
		objective_sha256: "3".repeat(64),
		dependency_manifest_sha256: "4".repeat(64),
	};
	Fixture {
		params,
		bytes,
		weight_offset: PREFIX_BYTES + padding,
		bias_offset: PREFIX_BYTES + padding + weights.len(),
	}
}

async fn compile(fixture: &Fixture) -> Result<F16Proposal> {
	let directory = tempfile::tempdir()?;
	let path = directory.path().join("source.safetensors");
	tokio::fs::write(&path, &fixture.bytes).await?;
	let mut file = tokio::fs::File::open(&path).await?;
	let result = compile_from_admitted(&fixture.params, &mut file).await;
	assert_eq!(tokio::fs::read(&path).await?, fixture.bytes);
	let mut entries = tokio::fs::read_dir(directory.path()).await?;
	assert_eq!(entries.next_entry().await?.unwrap().path(), path);
	assert!(entries.next_entry().await?.is_none());
	result
}

fn change_header(fixture: &mut Fixture, update: impl FnOnce(&mut Value)) {
	let mut header: Value = serde_json::from_slice(&fixture.bytes[8..PREFIX_BYTES]).unwrap();
	update(&mut header);
	fixture.bytes = pack(&header, &fixture.bytes[PREFIX_BYTES..]);
	fixture.params.source_sha256 = sha(&fixture.bytes);
}

#[tokio::test]
async fn coupled_exact_bytes_match_independent_candidate_and_inverse_oracles() {
	let mut f = fixture(&[0x3c00, 0x4200], &[0x8000], 3);
	f.params.members[1].role = ReadSetRole::EditTarget;
	f.params.members[1].edits = vec![ExactElementEdit {
		index: 0,
		expected_hex: "0080".into(),
		replacement_hex: "0000".into(),
	}];
	let proposal = compile(&f).await.unwrap();
	assert!(!proposal.is_keep());
	assert_eq!(proposal.requested_elements, 2);
	assert_eq!(proposal.changed_elements, 2);
	let mut expected = f.bytes.clone();
	expected[f.weight_offset..f.weight_offset + 2].copy_from_slice(&0x4000_u16.to_le_bytes());
	expected[f.bias_offset..f.bias_offset + 2].copy_from_slice(&0_u16.to_le_bytes());
	assert_eq!(proposal.candidate_sha256, sha(&expected));
	assert_eq!(proposal.source_sha256, sha(&f.bytes));
	assert_eq!(proposal.raw_prefix_sha256, sha(&f.bytes[..PREFIX_BYTES]));
	assert_eq!(proposal.json_header_sha256, sha(&f.bytes[8..PREFIX_BYTES]));
	assert_ne!(proposal.raw_prefix_sha256, proposal.json_header_sha256);
	let request = proposal.cohort_proposal().unwrap();
	assert_eq!(request.members.len(), 2);
	assert!(matches!(
		&request.training,
		cohort::TrainingContract::InferenceOnly
	));
	assert_eq!(request.expected_sha256, sha(&f.bytes));
	for member in &request.members {
		let start = if member.tensor_name == "weights" {
			f.weight_offset
		} else {
			assert_eq!(member.tensor_name, "bias");
			f.bias_offset
		};
		for edit in &member.edits {
			let at = start + 2 * usize::try_from(edit.index).unwrap();
			assert_eq!(
				&expected[at..at + 2],
				weight_tensor::unhex(&edit.replacement_hex).unwrap()
			);
			expected[at..at + 2]
				.copy_from_slice(&weight_tensor::unhex(&edit.expected_hex).unwrap());
		}
	}
	assert_eq!(expected, f.bytes);
	assert!(
		!proposal.production_eligible
			&& !proposal.behavior_evaluated
			&& !proposal.replacement_encoding_performed
	);
}

#[tokio::test]
async fn identity_preserves_negative_zero_and_subnormals_after_source_validation() {
	let values = [0x8000, 0x0001, 0x03ff, 0x0400, 0x7bff];
	let mut f = fixture(&values, &[0x8000], 1);
	f.params.members[0].edits = values
		.iter()
		.enumerate()
		.map(|(index, value)| ExactElementEdit {
			index: index as u64,
			expected_hex: hex(&value.to_le_bytes()),
			replacement_hex: hex(&value.to_le_bytes()),
		})
		.collect();
	f.params.maximum_update_l2_norm = 0.;
	f.params.members[0].maximum_update_l2_norm = 0.;
	let result = compile(&f).await.unwrap();
	assert!(result.is_keep());
	assert_eq!(result.requested_elements, 5);
	assert_eq!(result.changed_elements, 0);
	assert_eq!(result.candidate_sha256, f.params.source_sha256);
	assert_eq!(result.read_set.len(), 2);
	f.params.members[1].binding.payload_sha256 = "0".repeat(64);
	assert!(
		compile(&f).await.is_err(),
		"KEEP must not bypass dependency authentication"
	);
}

#[tokio::test]
async fn signed_zero_byte_change_is_not_keep_even_with_zero_norm() {
	let mut f = fixture(&[0x8000], &[0], 0);
	f.params.members[0].edits[0].replacement_hex = "0000".into();
	f.params.members[0].maximum_update_l2_norm = 0.;
	f.params.maximum_update_l2_norm = 0.;
	let result = compile(&f).await.unwrap();
	assert!(!result.is_keep());
	assert_eq!(result.changed_elements, 1);
	assert_eq!(result.global_budget.squared_update_units_hex, "0");
}

#[test]
fn f16_exact_decoder_matches_fixed_binary32_patterns_and_rejects_nonfinite() {
	for (input, expected) in [
		(0x0000_u16, 0x00000000_u32),
		(0x8000, 0x80000000),
		(0x0001, 0x33800000),
		(0x03ff, 0x387fc000),
		(0x0400, 0x38800000),
		(0x3c00, 0x3f800000),
		(0xbc00, 0xbf800000),
		(0x7bff, 0x477fe000),
	] {
		assert_eq!(
			represented_value(&hex(&input.to_le_bytes()))
				.unwrap()
				.to_bits(),
			expected
		);
	}
	for bits in [0x7c00_u16, 0xfc00, 0x7e00, 0x7c01, 0xffff] {
		assert!(represented_value(&hex(&bits.to_le_bytes())).is_err());
	}
}

#[tokio::test]
async fn nonfinite_expected_replacement_and_identity_are_rejected() {
	for bits in [0x7c00_u16, 0xfc00, 0x7e00, 0xffff] {
		let mut f = fixture(&[0x3c00], &[0], 0);
		f.params.members[0].edits[0].replacement_hex = hex(&bits.to_le_bytes());
		assert!(compile(&f).await.is_err());
		let mut identity = fixture(&[bits], &[0], 0);
		identity.params.members[0].edits[0].replacement_hex = hex(&bits.to_le_bytes());
		assert!(compile(&identity).await.is_err());
	}
}

#[tokio::test]
async fn wrong_expected_bytes_duplicate_and_out_of_range_indices_fail() {
	for variant in 0..3 {
		let mut f = fixture(&[0x3c00], &[0], 0);
		match variant {
			0 => f.params.members[0].edits[0].expected_hex = "0000".into(),
			1 => {
				let edit = f.params.members[0].edits[0].clone();
				f.params.members[0].edits.push(edit);
			}
			_ => f.params.members[0].edits[0].index = 1,
		}
		assert!(compile(&f).await.is_err());
	}
}

#[tokio::test]
async fn complete_source_hash_covers_unselected_bytes() {
	let mut f = fixture(&[0x3c00], &[0], 3);
	f.bytes[PREFIX_BYTES] = 17;
	assert!(compile(&f).await.is_err());
	f.params.source_sha256 = sha(&f.bytes);
	assert!(
		compile(&f).await.is_ok(),
		"the unselected byte is accepted only with its new complete commitment"
	);
}

#[tokio::test]
async fn unchanged_dependency_is_still_authenticated_as_a_full_payload() {
	let mut f = fixture(&[0x3c00], &[0, 0], 0);
	f.bytes[f.bias_offset + 3] = 0x3c;
	f.params.source_sha256 = sha(&f.bytes);
	assert!(compile(&f).await.is_err());
	f.params.members[1].binding.payload_sha256 = sha(&f.bytes[f.bias_offset..]);
	let proposal = compile(&f).await.unwrap();
	assert_eq!(proposal.read_set.len(), 2);
	assert_eq!(proposal.read_set[1].role, ReadSetRole::Dependency);
	assert_eq!(proposal.read_set[1].checked_elements, 0);
	assert_eq!(proposal.cohort_proposal().unwrap().members.len(), 1);
}

#[tokio::test]
async fn selected_tensor_shape_dtype_payload_and_name_are_bound() {
	for variant in 0..4 {
		let mut f = fixture(&[0x3c00], &[0], 0);
		match variant {
			0 => f.params.members[0].binding.shape = vec![1],
			1 => f.params.members[0].binding.dtype = "BF16".into(),
			2 => f.params.members[0].binding.payload_sha256 = "0".repeat(64),
			_ => f.params.members[0].binding.name = "missing".into(),
		}
		assert!(compile(&f).await.is_err());
	}
}

#[tokio::test]
async fn duplicate_header_gap_overlap_trailing_and_unknown_storage_fail_closed() {
	for variant in 0..5 {
		let mut f = fixture(&[0x3c00], &[0], 1);
		match variant {
			0 => {
				let mut header=br#"{"weights":{"dtype":"F16","shape":[1],"data_offsets":[0,2]},"weights":{"dtype":"F16","shape":[1],"data_offsets":[0,2]}}"#.to_vec();
				header.resize(HEADER_BYTES, b' ');
				f.bytes[8..PREFIX_BYTES].copy_from_slice(&header);
			}
			1 => change_header(&mut f, |h| {
				h["padding"]["shape"] = json!([0]);
				h["padding"]["data_offsets"] = json!([0, 0]);
			}),
			2 => change_header(&mut f, |h| h["bias"]["data_offsets"] = json!([1, 3])),
			3 => f.bytes.push(0),
			_ => change_header(&mut f, |h| h["padding"]["dtype"] = json!("UNVERIFIED")),
		}
		f.params.source_sha256 = sha(&f.bytes);
		assert!(compile(&f).await.is_err());
	}
}

#[tokio::test]
async fn original_total_cap_counts_identity_edits_before_filtering() {
	let mut f = fixture(&[0; 1024], &[0], 0);
	f.params.members[0].edits = (0..1024)
		.map(|index| ExactElementEdit {
			index,
			expected_hex: "0000".into(),
			replacement_hex: "0000".into(),
		})
		.collect();
	let result = compile(&f).await.unwrap();
	assert!(result.is_keep());
	assert_eq!(result.requested_elements, 1024);
	f.params.members[1].role = ReadSetRole::EditTarget;
	f.params.members[1].edits = vec![ExactElementEdit {
		index: 0,
		expected_hex: "0000".into(),
		replacement_hex: "0000".into(),
	}];
	assert!(
		compile(&f).await.is_err(),
		"1025 total is not reduced to zero before admission"
	);
}

#[tokio::test]
async fn exact_member_and_joint_norm_budgets_are_both_enforced() {
	let mut f = fixture(&[0x3c00], &[0x3c00], 0);
	f.params.members[0].maximum_update_l2_norm = 0.5;
	assert!(compile(&f).await.is_err());
	f.params.members[0].maximum_update_l2_norm = 1.;
	f.params.members[1].role = ReadSetRole::EditTarget;
	f.params.members[1].edits = vec![ExactElementEdit {
		index: 0,
		expected_hex: "003c".into(),
		replacement_hex: "0040".into(),
	}];
	f.params.members[1].maximum_update_l2_norm = 1.;
	f.params.maximum_update_l2_norm = 1.;
	assert!(compile(&f).await.is_err());
	f.params.maximum_update_l2_norm = 1.5;
	let proposal = compile(&f).await.unwrap();
	assert_eq!(proposal.changed_elements, 2);
	assert!(proposal
		.member_budgets
		.iter()
		.all(|budget| budget.within_budget));
	assert!(proposal.global_budget.within_budget);
}

#[tokio::test]
async fn split_element_at_stream_boundary_preserves_both_bytes_and_candidate_hash() {
	let mut f = fixture(&[0x3c00, 0x4200], &[0], 1024 * 1024 - 1 - PREFIX_BYTES);
	assert_eq!(f.weight_offset, 1024 * 1024 - 1);
	let proposal = compile(&f).await.unwrap();
	let mut expected = f.bytes.clone();
	expected[f.weight_offset..f.weight_offset + 2].copy_from_slice(&0x4000_u16.to_le_bytes());
	assert_eq!(proposal.candidate_sha256, sha(&expected));
	f.params.members[0].edits[0].expected_hex = "0040".into();
	assert!(
		compile(&f).await.is_err(),
		"mismatch is in the second chunk's byte"
	);
}

#[tokio::test]
async fn dependency_roles_and_member_uniqueness_do_not_bypass_admission() {
	for variant in 0..4 {
		let mut f = fixture(&[0x3c00], &[0], 0);
		match variant {
			0 => f.params.members[0].role = ReadSetRole::Dependency,
			1 => f.params.members[1].role = ReadSetRole::EditTarget,
			2 => f.params.members[1].binding.name = "weights".into(),
			_ => f.params.path = "../not-admitted".into(),
		}
		assert!(compile(&f).await.is_err());
	}
}

#[tokio::test]
async fn truncated_file_and_over_owner_size_are_rejected() {
	let mut f = fixture(&[0x3c00], &[0], 0);
	f.bytes.pop();
	assert!(compile(&f).await.is_err());
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("too-large.safetensors");
	let file = tokio::fs::File::create(&path).await.unwrap();
	file.set_len(2 * 1024 * 1024 * 1024 + 1).await.unwrap();
	drop(file);
	let mut file = tokio::fs::File::open(&path).await.unwrap();
	assert!(compile_from_admitted(&f.params, &mut file).await.is_err());
}

#[tokio::test]
async fn source_over_32_mib_matches_an_independent_streaming_oracle() {
	let padding = 33 * 1024 * 1024;
	let small = fixture(&[0x3c00], &[0], 0);
	let mut params = small.params;
	let header = json!({
		"padding":{"dtype":"U8","shape":[padding],"data_offsets":[0,padding]},
		"weights":{"dtype":"F16","shape":[1,1],"data_offsets":[padding,padding+2]},
		"bias":{"dtype":"F16","shape":[1],"data_offsets":[padding+2,padding+4]}
	});
	let prefix = pack(&header, &[]);
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("large-synthetic.safetensors");
	let mut file = tokio::fs::File::create(&path).await.unwrap();
	file.write_all(&prefix).await.unwrap();
	file.seek(std::io::SeekFrom::Start((PREFIX_BYTES + padding) as u64))
		.await
		.unwrap();
	file.write_all(&[0x00, 0x3c, 0x00, 0x00]).await.unwrap();
	drop(file);
	let zeroes = [0_u8; 4096];
	let mut source_hash = Sha256::new();
	source_hash.update(&prefix);
	for _ in 0..padding / zeroes.len() {
		source_hash.update(zeroes);
	}
	let mut target_hash = source_hash.clone();
	source_hash.update([0x00, 0x3c, 0x00, 0x00]);
	target_hash.update([0x00, 0x40, 0x00, 0x00]);
	params.source_sha256 = hex(&source_hash.finalize());
	let mut file = tokio::fs::File::open(&path).await.unwrap();
	let proposal = compile_from_admitted(&params, &mut file).await.unwrap();
	assert_eq!(
		proposal.source_size_bytes,
		(PREFIX_BYTES + padding + 4) as u64
	);
	assert_eq!(proposal.candidate_sha256, hex(&target_hash.finalize()));
	assert_eq!(proposal.read_set.len(), 2);
	assert_eq!(proposal.requested_elements, 1);
	assert!(!proposal.production_eligible);
}
