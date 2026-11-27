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

//! Authored synthetic controls for the actual descriptor-based evaluation API.
//! Fixed dyadic/bit oracles are independent of the reused numerical kernel.

use super::super::super::weight_f16_proposal::{Member, TensorBinding};
use super::super::super::weight_tensor::ExactElementEdit;
use super::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const HEADER_BYTES: usize = 4096;
const PREFIX_BYTES: usize = 8 + HEADER_BYTES;

struct Tensor {
	name: String,
	shape: Vec<u64>,
	values: Vec<u16>,
}

impl Tensor {
	fn new(name: &str, shape: &[u64], values: &[u16]) -> Self {
		Self {
			name: name.into(),
			shape: shape.to_vec(),
			values: values.to_vec(),
		}
	}
}

#[derive(Clone)]
struct Fixture {
	params: CoupledF16EvaluationParams,
	bytes: Vec<u8>,
	offsets: BTreeMap<String, usize>,
}

fn raw(values: &[u16]) -> Vec<u8> {
	values
		.iter()
		.flat_map(|value| value.to_le_bytes())
		.collect()
}

fn element_hex(value: u16) -> String {
	let [a, b] = value.to_le_bytes();
	format!("{a:02x}{b:02x}")
}

// Deliberately assemble a separate byte vector rather than using the evaluator's
// streaming commitment function to manufacture its expected hash.
fn expected_rows(features: &FeatureBatch) -> String {
	let mut bytes = b"hepta.weight.coupled-f16-feature-rows.v1\0".to_vec();
	bytes.extend((features.rows.len() as u64).to_le_bytes());
	bytes.extend((features.rows[0].len() as u64).to_le_bytes());
	for (id, row) in features.sample_ids.iter().zip(&features.rows) {
		for at in (0..64).step_by(2) {
			bytes.push(u8::from_str_radix(&id[at..at + 2], 16).unwrap());
		}
		for value in row {
			bytes.extend(value.to_bits().to_le_bytes());
		}
	}
	sha(&bytes)
}

fn refresh_rows(f: &mut Fixture, rows: Vec<Vec<f32>>) {
	f.params.features.sample_ids = (0..rows.len())
		.map(|index| format!("{index:064x}"))
		.collect();
	f.params.features.rows = rows;
	f.params.features.expected_rows_sha256 = expected_rows(&f.params.features);
	let outputs = f
		.params
		.proposal
		.members
		.iter()
		.find(|member| member.binding.name == f.params.head.bias_name)
		.unwrap()
		.binding
		.shape[0];
	f.params.objective = Objective::SquaredError {
		targets: vec![vec![0.0; outputs as usize]; f.params.features.rows.len()],
	};
}

fn edits(f: &mut Fixture, name: &str, changes: &[(usize, u16)]) {
	let offset = f.offsets[name];
	let member = f
		.params
		.proposal
		.members
		.iter_mut()
		.find(|member| member.binding.name == name)
		.unwrap();
	member.role = if changes.is_empty() {
		ReadSetRole::Dependency
	} else {
		ReadSetRole::EditTarget
	};
	member.edits = changes
		.iter()
		.map(|(index, replacement)| {
			let at = offset + 2 * index;
			ExactElementEdit {
				index: *index as u64,
				expected_hex: format!("{:02x}{:02x}", f.bytes[at], f.bytes[at + 1]),
				replacement_hex: element_hex(*replacement),
			}
		})
		.collect();
}

fn fixture(
	tensors: Vec<Tensor>,
	head: (&str, &str),
	rows: Vec<Vec<f32>>,
	padding: usize,
) -> Fixture {
	let mut header = json!({
		"padding": {"dtype": "U8", "shape": [padding], "data_offsets": [0,padding]},
		"__metadata__": {"fixture": "synthetic coupled F16 comparison"}
	});
	let mut payload = vec![0_u8; padding];
	let mut members = Vec::new();
	let mut offsets = BTreeMap::new();
	for tensor in tensors {
		assert_eq!(
			tensor.shape.iter().product::<u64>() as usize,
			tensor.values.len()
		);
		let bytes = raw(&tensor.values);
		let start = payload.len();
		payload.extend_from_slice(&bytes);
		header[tensor.name.as_str()] = json!({
			"dtype": "F16", "shape": &tensor.shape, "data_offsets": [start,payload.len()]
		});
		offsets.insert(tensor.name.clone(), PREFIX_BYTES + start);
		members.push(Member {
			binding: TensorBinding {
				name: tensor.name,
				dtype: "F16".into(),
				shape: tensor.shape,
				payload_sha256: sha(&bytes),
			},
			role: ReadSetRole::Dependency,
			edits: Vec::new(),
			maximum_update_l2_norm: 1_000_000.0,
		});
	}
	let mut header = serde_json::to_vec(&header).unwrap();
	assert!(header.len() <= HEADER_BYTES);
	header.resize(HEADER_BYTES, b' ');
	let mut bytes = (HEADER_BYTES as u64).to_le_bytes().to_vec();
	bytes.extend(header);
	bytes.extend(payload);
	let source_sha256 = sha(&bytes);
	let mut f = Fixture {
		params: CoupledF16EvaluationParams {
			proposal: F16ProposalParams {
				request_id: "1".repeat(64),
				path: "/not-opened/coupled-fixture.safetensors".into(),
				source_sha256: source_sha256.clone(),
				members,
				maximum_update_l2_norm: 1_000_000.0,
				data_manifest_sha256: "2".repeat(64),
				objective_sha256: "3".repeat(64),
				dependency_manifest_sha256: "4".repeat(64),
			},
			head: HeadSelection {
				weight_name: head.0.into(),
				bias_name: head.1.into(),
			},
			features: FeatureBatch {
				origin: FeatureOrigin::SyntheticControl,
				source_checkpoint_sha256: source_sha256,
				source_domain_sha256: "5".repeat(64),
				producer_code_sha256: "6".repeat(64),
				producer_configuration_sha256: "7".repeat(64),
				declared_producer_receipt_sha256: "8".repeat(64),
				data_manifest_sha256: "2".repeat(64),
				sample_ids: Vec::new(),
				expected_rows_sha256: String::new(),
				rows: Vec::new(),
			},
			objective: Objective::SquaredError {
				targets: Vec::new(),
			},
			constraints: Vec::new(),
			minimum_gain: 0.0,
		},
		bytes,
		offsets,
	};
	refresh_rows(&mut f, rows);
	edits(&mut f, head.0, &[(0, 0x4000)]);
	f
}

fn small() -> Fixture {
	fixture(
		vec![
			Tensor::new("weights", &[1, 1], &[0x3c00]),
			Tensor::new("bias", &[1], &[0]),
		],
		("weights", "bias"),
		vec![vec![1.0]],
		3,
	)
}

async fn evaluate(f: &Fixture) -> Result<CoupledF16Evaluation> {
	let directory = tempfile::tempdir()?;
	let path = directory.path().join("source.safetensors");
	tokio::fs::write(&path, &f.bytes).await?;
	let mut file = tokio::fs::File::open(&path).await?;
	let result = evaluate_from_admitted(&f.params, &mut file).await;
	assert_eq!(tokio::fs::read(&path).await?, f.bytes);
	let mut entries = tokio::fs::read_dir(directory.path()).await?;
	assert_eq!(entries.next_entry().await?.unwrap().path(), path);
	assert!(entries.next_entry().await?.is_none());
	result
}

async fn compile_only(f: &Fixture) -> Result<F16Proposal> {
	let directory = tempfile::tempdir()?;
	let path = directory.path().join("source.safetensors");
	tokio::fs::write(&path, &f.bytes).await?;
	let mut file = tokio::fs::File::open(&path).await?;
	let result = weight_f16_proposal::compile_from_admitted(&f.params.proposal, &mut file).await;
	assert_eq!(tokio::fs::read(path).await?, f.bytes);
	result
}

#[tokio::test]
async fn coupled_weights_and_bias_match_independent_dyadic_oracles() {
	let mut f = fixture(
		vec![
			Tensor::new("weights", &[2, 2], &[0x3c00, 0x4000, 0xbc00, 0x3800]),
			Tensor::new("bias", &[2], &[0x3800, 0xb800]),
		],
		("weights", "bias"),
		vec![vec![2.0, 4.0]],
		3,
	);
	edits(&mut f, "weights", &[(0, 0x4000), (3, 0x3c00)]);
	edits(&mut f, "bias", &[(0, 0xb800), (1, 0x3800)]);
	f.params.objective = Objective::SquaredError {
		targets: vec![vec![11.5, 2.5]],
	};
	let result = evaluate(&f).await.unwrap();
	assert_eq!(result.baseline_predictions, vec![vec![10.5, -0.5]]);
	assert_eq!(result.candidate_predictions, vec![vec![11.5, 2.5]]);
	assert_ne!(result.candidate_predictions, vec![vec![12.5, 1.5]]); // Incorrect old bias.
	assert_eq!(result.baseline_score, -5.0);
	assert_eq!(result.candidate_score, 0.0);
	assert_eq!(result.gain, 5.0);
	assert!(result.supplied_row_condition_satisfied);
	assert_eq!(
		result.weight.candidate_sha256,
		sha(&raw(&[0x4000, 0x4000, 0xbc00, 0x3c00]))
	);
	assert_eq!(result.bias.candidate_sha256, sha(&raw(&[0xb800, 0x3800])));
	assert_eq!(result.proposal.cohort_proposal().unwrap().members.len(), 2);
	assert!(!result.production_eligible);
}

#[tokio::test]
async fn one_member_edits_still_authenticate_the_other_complete_payload() {
	let mut bias_only = fixture(
		vec![
			Tensor::new("weights", &[1, 1], &[0x3c00]),
			Tensor::new("bias", &[1], &[0x3800]),
		],
		("weights", "bias"),
		vec![vec![2.0]],
		0,
	);
	edits(&mut bias_only, "weights", &[]);
	edits(&mut bias_only, "bias", &[(0, 0x3c00)]);
	let result = evaluate(&bias_only).await.unwrap();
	assert_eq!(result.baseline_predictions, vec![vec![2.5]]);
	assert_eq!(result.candidate_predictions, vec![vec![3.0]]);
	let mut bad = bias_only.clone();
	bad.params.proposal.members[0].binding.payload_sha256 = "a".repeat(64);
	assert!(evaluate(&bad).await.is_err());
	let mut weight_only = bias_only;
	edits(&mut weight_only, "weights", &[(0, 0x4000)]);
	edits(&mut weight_only, "bias", &[]);
	assert_eq!(
		evaluate(&weight_only).await.unwrap().candidate_predictions,
		vec![vec![4.5]]
	);
	weight_only.params.proposal.members[1]
		.binding
		.payload_sha256 = "b".repeat(64);
	assert!(evaluate(&weight_only).await.is_err());
}

#[tokio::test]
async fn full_synthetic_act_and_price_pairs_fit_individually() {
	for (name, outputs, columns, count, expected) in [
		("act_head.2", 2, 256, 514, 513.0),
		("scorer.3", 1, 768, 769, 1537.0),
	] {
		let weight = format!("{name}.weight");
		let bias = format!("{name}.bias");
		let mut f = fixture(
			vec![
				Tensor::new(
					&weight,
					&[outputs, columns],
					&vec![0x3c00; (outputs * columns) as usize],
				),
				Tensor::new(&bias, &[outputs], &vec![0; outputs as usize]),
			],
			(&weight, &bias),
			vec![vec![1.0; columns as usize]],
			0,
		);
		edits(
			&mut f,
			&weight,
			&(0..(outputs * columns) as usize)
				.map(|i| (i, 0x4000))
				.collect::<Vec<_>>(),
		);
		edits(
			&mut f,
			&bias,
			&(0..outputs as usize)
				.map(|i| (i, 0x3c00))
				.collect::<Vec<_>>(),
		);
		f.params.objective = Objective::SquaredError {
			targets: vec![vec![expected; outputs as usize]],
		};
		let result = evaluate(&f).await.unwrap();
		let requested: usize = result
			.proposal
			.cohort_proposal()
			.unwrap()
			.members
			.iter()
			.map(|member| member.edits.len())
			.sum();
		assert_eq!(requested, count);
		assert_eq!(
			result.baseline_predictions,
			vec![vec![columns as f64; outputs as usize]]
		);
		assert_eq!(
			result.candidate_predictions,
			vec![vec![f64::from(expected); outputs as usize]]
		);
		assert!(result.supplied_row_condition_satisfied);
		assert_eq!(result.features.origin, FeatureOrigin::SyntheticControl);
		assert!(!result.features.feature_provenance_verified);
	}
}

#[tokio::test]
async fn combined_full_and_sparse_two_head_requests_keep_distinct_rejection_boundaries() {
	let mut f = fixture(
		vec![
			Tensor::new("act_w", &[2, 256], &vec![0x3c00; 512]),
			Tensor::new("act_b", &[2], &[0, 0]),
			Tensor::new("price_w", &[1, 768], &vec![0x3c00; 768]),
			Tensor::new("price_b", &[1], &[0]),
		],
		("act_w", "act_b"),
		vec![vec![1.0; 256]],
		0,
	);
	for (name, count) in [
		("act_w", 512),
		("act_b", 2),
		("price_w", 768),
		("price_b", 1),
	] {
		edits(
			&mut f,
			name,
			&(0..count).map(|index| (index, 0x4000)).collect::<Vec<_>>(),
		);
	}
	assert_eq!(
		f.params
			.proposal
			.members
			.iter()
			.map(|member| member.edits.len())
			.sum::<usize>(),
		1283
	);
	assert!(compile_only(&f)
		.await
		.err()
		.unwrap()
		.to_string()
		.contains("1024"));
	assert!(evaluate(&f).await.is_err());
	edits(&mut f, "act_w", &[(0, 0x4000)]);
	edits(&mut f, "price_w", &[(0, 0x4000)]);
	edits(&mut f, "act_b", &[]);
	edits(&mut f, "price_b", &[]);
	assert!(compile_only(&f).await.is_ok()); // Sparse proposal is legal for the compiler.
	assert!(evaluate(&f)
		.await
		.err()
		.unwrap()
		.to_string()
		.contains("exactly one"));
}

#[tokio::test]
async fn source_shape_dtype_and_complete_commitments_are_mandatory() {
	let original = small();
	let mut missing = original.clone();
	missing.params.proposal.members.pop();
	assert!(evaluate(&missing).await.is_err());
	for shape in [vec![1, 1], vec![2], Vec::new()] {
		let mut bad = original.clone();
		bad.params.proposal.members[1].binding.shape = shape;
		assert!(evaluate(&bad).await.is_err());
	}
	let mut repeated = original.clone();
	repeated
		.params
		.proposal
		.members
		.push(repeated.params.proposal.members[0].clone());
	assert!(evaluate(&repeated).await.is_err());
	let mut dtype = original.clone();
	dtype.params.proposal.members[0].binding.dtype = "BF16".into();
	assert!(evaluate(&dtype).await.is_err());
	let mut bad_payload = original.clone();
	bad_payload.params.proposal.members[0]
		.binding
		.payload_sha256 = "a".repeat(64);
	assert!(evaluate(&bad_payload).await.is_err());
	let mut unselected = original;
	unselected.bytes[PREFIX_BYTES] ^= 1;
	assert!(evaluate(&unselected).await.is_err());
}

#[tokio::test]
async fn unedited_nonfinite_selected_values_reject_and_finite_decode_is_exact() {
	for nonfinite in [0x7c00, 0xfc00, 0x7e01] {
		let f = fixture(
			vec![
				Tensor::new("weights", &[1, 2], &[0x3c00, nonfinite]),
				Tensor::new("bias", &[1], &[0]),
			],
			("weights", "bias"),
			vec![vec![1.0, 1.0]],
			0,
		);
		assert!(compile_only(&f).await.is_ok());
		assert!(evaluate(&f)
			.await
			.err()
			.unwrap()
			.to_string()
			.contains("every selected coefficient"));
		let f = fixture(
			vec![
				Tensor::new("weights", &[1, 1], &[0x3c00]),
				Tensor::new("bias", &[1], &[nonfinite]),
			],
			("weights", "bias"),
			vec![vec![1.0]],
			0,
		);
		assert!(compile_only(&f).await.is_ok());
		assert!(evaluate(&f).await.is_err());
	}
	let actual: Vec<_> = source::decode(&raw(&[0, 0x8000, 1, 0x03ff, 0x0400, 0x7bff, 0x8001]))
		.unwrap()
		.into_iter()
		.map(f32::to_bits)
		.collect();
	assert_eq!(
		actual,
		vec![0, 0x80000000, 0x33800000, 0x387fc000, 0x38800000, 0x477fe000, 0xb3800000]
	);
}

#[tokio::test]
async fn keep_and_signed_zero_never_bypass_source_or_strict_gain_checks() {
	let mut keep = small();
	edits(&mut keep, "weights", &[(0, 0x3c00)]);
	let result = evaluate(&keep).await.unwrap();
	assert!(result.proposal.is_keep());
	assert_eq!(result.gain, 0.0);
	assert!(!result.supplied_row_condition_satisfied);
	let mut bad = keep;
	bad.params.proposal.members[1].binding.payload_sha256 = "a".repeat(64);
	assert!(evaluate(&bad).await.is_err());
	let mut zero = fixture(
		vec![
			Tensor::new("weights", &[1, 1], &[0x8000]),
			Tensor::new("bias", &[1], &[0]),
		],
		("weights", "bias"),
		vec![vec![1.0]],
		0,
	);
	edits(&mut zero, "weights", &[(0, 0)]);
	zero.params.proposal.maximum_update_l2_norm = 0.0;
	zero.params.proposal.members[0].maximum_update_l2_norm = 0.0;
	let result = evaluate(&zero).await.unwrap();
	assert!(!result.proposal.is_keep());
	assert_ne!(
		result.weight.original_sha256,
		result.weight.candidate_sha256
	);
	assert_eq!(result.gain, 0.0);
	assert!(!result.supplied_row_condition_satisfied);
	assert!(!result.production_eligible);
}

#[tokio::test]
async fn feature_commitments_reject_mismatch_and_never_certify_a_producer() {
	let mut original = small();
	refresh_rows(&mut original, vec![vec![1.0], vec![2.0]]);
	for index in 0..8 {
		let mut bad = original.clone();
		match index {
			0 => bad.params.features.source_checkpoint_sha256 = "a".repeat(64),
			1 => bad.params.features.data_manifest_sha256 = "a".repeat(64),
			2 => bad.params.features.source_domain_sha256 = "A".repeat(64),
			3 => bad.params.features.declared_producer_receipt_sha256 = "0".repeat(63),
			4 => bad.params.features.sample_ids.swap(0, 1),
			5 => bad.params.features.sample_ids[1] = bad.params.features.sample_ids[0].clone(),
			6 => bad.params.features.rows[0][0] = -0.0,
			_ => bad.params.features.expected_rows_sha256 = "a".repeat(64),
		}
		assert!(evaluate(&bad).await.is_err());
	}
	for origin in [
		FeatureOrigin::SyntheticControl,
		FeatureOrigin::DeclaredEncoderOutput,
	] {
		original.params.features.origin = origin;
		let result = evaluate(&original).await.unwrap();
		assert_eq!(result.features.origin, origin);
		assert!(!result.features.producer_execution_verified);
		assert!(!result.features.feature_provenance_verified);
		assert!(!result.head_semantics_verified);
		assert!(!result.independent_holdout_verified);
	}
}

#[tokio::test]
async fn different_before_after_feature_spaces_are_not_accepted_as_affine_transfer() {
	let f = small();
	let value = serde_json::to_value(&f.params).unwrap();
	assert!(serde_json::from_value::<CoupledF16EvaluationParams>(value.clone()).is_ok());
	for extra in ["old_features", "new_features", "candidate_features"] {
		let mut invalid = value.clone();
		invalid[extra] = json!([[1.0]]);
		assert!(serde_json::from_value::<CoupledF16EvaluationParams>(invalid).is_err());
	}
	let mut invalid = value;
	invalid["features"]["producer_execution_verified"] = json!(true);
	assert!(serde_json::from_value::<CoupledF16EvaluationParams>(invalid).is_err());
}

#[tokio::test]
async fn two_forwards_share_one_compute_and_serialization_budget() {
	let mut macs = small();
	macs.params.proposal.members[0].binding.shape = vec![256, 1024];
	macs.params.proposal.members[1].binding.shape = vec![256];
	refresh_rows(&mut macs, vec![vec![1.0; 1024]; 64]);
	assert!(evaluate(&macs)
		.await
		.err()
		.unwrap()
		.to_string()
		.contains("together exceed"));
	let mut outputs = small();
	outputs.params.proposal.members[0].binding.shape = vec![4096, 1];
	outputs.params.proposal.members[1].binding.shape = vec![4096];
	refresh_rows(&mut outputs, vec![vec![1.0]; 3]);
	assert!(evaluate(&outputs)
		.await
		.err()
		.unwrap()
		.to_string()
		.contains("together exceed"));
	let mut rows = small();
	refresh_rows(&mut rows, vec![vec![1.0]; 65]);
	assert!(evaluate(&rows).await.is_err());
	let mut large = small();
	refresh_rows(&mut large, vec![vec![1.0]; 64]);
	large.params.objective = Objective::SquaredError {
		targets: vec![vec![f32::MAX; 4096]; 64],
	};
	assert!(evaluate(&large)
		.await
		.err()
		.unwrap()
		.to_string()
		.contains("exceeds 1 MiB"));
}

#[tokio::test]
async fn actual_score_constraints_strict_threshold_and_overflow_are_preserved() {
	let mut f = small();
	f.params.objective = Objective::SquaredError {
		targets: vec![vec![2.0]],
	};
	f.params.minimum_gain = 1.0;
	let threshold = evaluate(&f).await.unwrap();
	assert_eq!(threshold.gain, 1.0);
	assert!(!threshold.supplied_row_condition_satisfied);
	f.params.minimum_gain = 0.0;
	f.params.constraints = vec![
		Constraint::Range {
			column: 0,
			lower: 0.0,
			upper: 1.5,
		},
		Constraint::Preserve {
			column: 0,
			max_absolute_change: 0.5,
		},
	];
	let violation = evaluate(&f).await.unwrap();
	assert!(violation.baseline_constraint_failures.is_empty());
	assert_eq!(violation.candidate_constraint_failures, vec![0, 1]);
	assert!(!violation.supplied_row_condition_satisfied);
	let mut bad = f.clone();
	bad.params.constraints = vec![Constraint::Range {
		column: 1,
		lower: 0.0,
		upper: 3.0,
	}];
	assert!(evaluate(&bad).await.is_err());
	let mut bad = f.clone();
	bad.params.objective = Objective::SquaredError {
		targets: vec![vec![2.0, 3.0]],
	};
	assert!(evaluate(&bad).await.is_err());
	let mut bad = f;
	bad.params.objective = Objective::SquaredError {
		targets: vec![vec![f32::NAN]],
	};
	assert!(evaluate(&bad).await.is_err());
	let mut action = fixture(
		vec![
			Tensor::new("weights", &[2, 1], &[0x3c00, 0x4000]),
			Tensor::new("bias", &[2], &[0, 0]),
		],
		("weights", "bias"),
		vec![vec![1.0]],
		0,
	);
	action.params.objective = Objective::ActionValue {
		action_columns: vec![0, 1],
		values: vec![vec![2.0, 1.0]],
	};
	let result = evaluate(&action).await.unwrap();
	assert_eq!(result.baseline_score, 1.0);
	assert_eq!(result.candidate_score, 2.0); // Original tie rule selects first listed action.
	let mut overflow = small();
	refresh_rows(&mut overflow, vec![vec![1.0e35]]);
	edits(&mut overflow, "weights", &[(0, 0x7bff)]);
	assert!(evaluate(&overflow)
		.await
		.err()
		.unwrap()
		.to_string()
		.contains("overflowed F32"));
	assert!(paired_predictions(vec![vec![1.0]], Vec::new(), 1, 1).is_err());
	assert!(paired_predictions(vec![vec![1.0]], vec![vec![1.0, 2.0]], 1, 1).is_err());
}

#[tokio::test]
async fn full_stream_capture_handles_chunk_boundaries_order_and_changed_source() {
	for bias_first in [false, true] {
		let tensors = if bias_first {
			vec![
				Tensor::new("bias", &[1], &[0]),
				Tensor::new("weights", &[1, 1], &[0x3c00]),
			]
		} else {
			vec![
				Tensor::new("weights", &[1, 1], &[0x3c00]),
				Tensor::new("bias", &[1], &[0]),
			]
		};
		let f = fixture(
			tensors,
			("weights", "bias"),
			vec![vec![1.0]],
			1024 * 1024 - PREFIX_BYTES - 1,
		);
		let first = if bias_first { "bias" } else { "weights" };
		assert_eq!(f.offsets[first], 1024 * 1024 - 1);
		assert_eq!(
			evaluate(&f).await.unwrap().candidate_predictions,
			vec![vec![2.0]]
		);
		let mut truncated = f.clone();
		truncated.bytes.pop();
		assert!(evaluate(&truncated).await.is_err());
	}
	// Controlled mutation between the real compiler and the same second-capture
	// helper, without a production hook or a concurrent writer assumption.
	let f = small();
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("source.safetensors");
	tokio::fs::write(&path, &f.bytes).await.unwrap();
	let mut file = tokio::fs::File::open(&path).await.unwrap();
	let _proposal = weight_f16_proposal::compile_from_admitted(&f.params.proposal, &mut file)
		.await
		.unwrap();
	let mut changed = f.bytes.clone();
	changed[PREFIX_BYTES] ^= 1;
	tokio::fs::write(&path, &changed).await.unwrap();
	assert!(source::capture(
		&f.params,
		validate(&f.params).unwrap(),
		&mut file,
		Instant::now() + Duration::from_secs(60)
	)
	.await
	.is_err());
	assert_eq!(tokio::fs::read(path).await.unwrap(), changed);
}

#[tokio::test]
async fn report_counts_both_hashes_and_forwards_without_owner_or_model_qualification() {
	let f = small();
	let result = evaluate(&f).await.unwrap();
	assert_eq!(result.cost.complete_source_hash_passes, 2);
	assert_eq!(
		result.cost.complete_pass_bytes_hashed,
		2 * f.bytes.len() as u64
	);
	assert_eq!(result.cost.directory_inspections, 2);
	assert_eq!(result.cost.linear_forward_calls, 2);
	assert_eq!(result.cost.operation_limit_seconds, 60);
	assert_eq!(result.cost.combined_multiply_adds, 2);
	assert!(!result.cost.parser_and_header_extra_io_bytes_known);
	assert!(!result.cost.end_to_end_cost_known);
	assert!(result.linear_kernel_evaluated);
	assert!(!result.full_model_executed);
	assert!(!result.owner_invoked);
	assert!(!result.artifact_created);
	assert!(!result.live_activation);
	assert!(!result.rollback_executed);
	assert!(!result.production_eligible);
	assert_eq!(
		result.features.rows_sha256,
		expected_rows(&f.params.features)
	);
	assert_eq!(
		result.proposal_sha256,
		sha(&serde_json::to_vec(&result.proposal).unwrap())
	);
	assert_eq!(
		result.weight.original_sha256,
		f.params.proposal.members[0].binding.payload_sha256
	);
	assert_eq!(
		result.bias.original_sha256,
		f.params.proposal.members[1].binding.payload_sha256
	);
	let bytes = serde_json::to_vec(&result).unwrap();
	assert!(bytes.len() <= 1024 * 1024);
	assert!(serde_json::from_slice::<Value>(&bytes).is_ok());
	// No runtime or performance threshold is inferred from this synthetic fixture.
}
