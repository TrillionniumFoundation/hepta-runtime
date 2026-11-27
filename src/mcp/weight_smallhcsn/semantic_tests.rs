// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Byte-bound semantic and hidden-scope controls; these tests run no model forward.

use super::*;
use crate::mcp::{weight_artifact::cohort::Identity, weight_hidden_scope as hidden};
use serde_json::json;

pub(in crate::mcp) struct Fixture {
	pub(in crate::mcp) profile: Vec<u8>,
	pub(in crate::mcp) artifact: Vec<u8>,
	pub(in crate::mcp) raw: Vec<u8>,
	pub(in crate::mcp) drive_offset: usize,
	pub(in crate::mcp) header_sha256: String,
}

pub(in crate::mcp) fn fixture(unmask_one: bool) -> Fixture {
	let mut raw = b"HCSNIN1\0".to_vec();
	for value in [1u32, 6, 2, 9] {
		raw.extend_from_slice(&value.to_le_bytes());
	}
	for value in std::iter::repeat_n(0.0f32, 9)
		.chain(std::iter::repeat_n(1.0f32, 10))
		.chain(std::iter::repeat_n(0.0f32, 110))
	{
		raw.extend_from_slice(&value.to_le_bytes());
	}
	raw.extend_from_slice(&0i64.to_le_bytes());
	let declarations = [
		("body.raw_cost", "F32", vec![8]),
		("body.raw_boundary", "F32", vec![8]),
		("body.fixed_boundary", "F64", vec![8]),
		("body.reset_absolute", "F64", vec![8]),
		("body.synaptic_mask", "F32", vec![8, 24]),
		("body.recurrent.weight", "F32", vec![8, 24]),
		("body.input_drive.weight", "F32", vec![4, 9]),
		("body.input_mark.weight", "F32", vec![4, 9]),
		("body.input_drive.bias", "F32", vec![4]),
		("body.input_mark.bias", "F32", vec![4]),
		("body.readout.weight", "F32", vec![2, 20]),
		("body.readout.bias", "F32", vec![2]),
	];
	let source = "1".repeat(64);
	let mut header = serde_json::Map::new();
	header.insert(
		"__metadata__".into(),
		json!({
			"source_checkpoint_sha256":source,
			"alias_map_json":"{\"head.weight\":\"body.readout.weight\",\"head.bias\":\"body.readout.bias\"}"
		}),
	);
	let mut payload = Vec::new();
	let mut pins = Vec::new();
	let mut drive_begin = 0;
	for (name, dtype, shape) in declarations {
		let begin = payload.len();
		if name == hidden::WEIGHT_NAME {
			drive_begin = begin;
		}
		for index in 0..shape.iter().product::<usize>() {
			let value = match name {
				"body.synaptic_mask" => {
					if index / 24 < 4
						&& (4..8).contains(&(index % 24))
						&& !(unmask_one && index == 4)
					{
						0.0f64
					} else {
						1.0f64
					}
				}
				"body.fixed_boundary" => -0.5,
				"body.reset_absolute" => 0.5,
				_ => 0.0,
			};
			if dtype == "F64" {
				payload.extend_from_slice(&value.to_le_bytes());
			} else {
				payload.extend_from_slice(&(value as f32).to_le_bytes());
			}
		}
		let end = payload.len();
		header.insert(
			name.into(),
			json!({"dtype":dtype,"shape":shape,"data_offsets":[begin,end]}),
		);
		pins.push(
			json!({"name":name,"dtype":dtype,"shape":shape,"data_offsets":[begin,end],
			"sha256":sha(&payload[begin..end]),"mutable":name=="body.readout.weight"}),
		);
	}
	let mut header = serde_json::to_vec(&header).unwrap();
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let mut artifact = (header.len() as u64).to_le_bytes().to_vec();
	artifact.extend_from_slice(&header);
	artifact.extend_from_slice(&payload);
	let profile = serde_json::to_vec(&json!({
		"schema":"hepta.native-smallhcsn-bound-profile.v1","input_sha256":sha(&raw),"input_bytes":raw.len(),
		"profiles":[{"seed":7,"canonical_sha256":sha(&artifact),"source_pt_sha256":source,
			"header_sha256":sha(&header),"header_length":header.len(),"file_bytes":artifact.len(),"tensors":pins}],
		"source_declarations":{"synthetic":true},
		"configuration":{"neurons":8,"bins":6,"refractory_stages":3,"ticks":6,"choices":2,"input_width":9,
			"dt":0.48,"sigma":0.55,"rho":0.3,"extent":2.0,"refractory":0.2,"gain":0.8,"maintenance":0.25,
			"mode":"qvi-boundary-centered-mixed-value-risk-no-feature-normalization"}
	})).unwrap();
	Fixture {
		profile,
		artifact,
		raw,
		drive_offset: 8 + header.len() + drive_begin,
		header_sha256: sha(&header),
	}
}

#[test]
fn semantic_roles_bind_actual_bytes_and_do_not_invent_head_or_ndu_semantics() {
	let f = fixture(false);
	let model = bind(&f.profile, &f.artifact, &f.raw).unwrap();
	let map = sender_semantic_map(&model).unwrap();
	assert_eq!(map["artifact_sha256"], sha(&f.artifact));
	assert_eq!(map["header_sha256"], f.header_sha256);
	assert_eq!(map["raw_input_sha256"], sha(&f.raw));
	assert_eq!(map["tensors"].as_array().unwrap().len(), 12);
	assert_eq!(map["protected_tensor_count"], 10);
	assert_eq!(map["allowed_parameters"]["maximum_coordinates"], 40);
	assert_eq!(map["recurrent"]["potentially_active_elements"], 48);
	assert_eq!(map["recurrent"]["inert_elements"], 144);
	assert_eq!(map["feature_groups"][3]["receiver_neuron"], 7);
	assert_eq!(map["feature_groups"][3]["feature_end_exclusive"], 20);
	assert_eq!(
		map["named_capability_limits"]["call_put_head_semantics_verified"],
		false
	);
	assert_eq!(
		map["named_capability_limits"]["learned_continuation_q_head_verified"],
		false
	);
	assert_eq!(
		map["named_capability_limits"]["ndu_controller_present"],
		false
	);
	assert_eq!(map["full_model_executed"], false);
	assert_eq!(map["model_calls"], 0);
	let raw_boundary = map["tensors"]
		.as_array()
		.unwrap()
		.iter()
		.find(|v| v["name"] == "body.raw_boundary")
		.unwrap();
	assert_eq!(raw_boundary["role"], "inactive_in_this_fixed_qvi_branch");
	assert_eq!(raw_boundary["protected_in_sender_scope"], true);
	let expected = map["semantic_map_sha256"].clone();
	let mut without = map;
	without
		.as_object_mut()
		.unwrap()
		.remove("semantic_map_sha256");
	assert_eq!(expected, sha(&serde_json::to_vec(&without).unwrap()));
}

#[test]
fn semantic_activity_is_computed_from_the_captured_mask_and_protected_tamper_fails() {
	let f = fixture(true);
	let model = bind(&f.profile, &f.artifact, &f.raw).unwrap();
	let map = sender_semantic_map(&model).unwrap();
	assert_eq!(map["recurrent"]["potentially_active_elements"], 49);
	assert_eq!(map["recurrent"]["inert_elements"], 143);
	let mut tampered = f.artifact.clone();
	*tampered.last_mut().unwrap() ^= 1;
	assert!(bind(&f.profile, &tampered, &f.raw).is_err());
}

#[test]
fn hidden_binding_rebuilds_actual_candidate_and_rejects_any_extra_tensor_change() {
	let f = fixture(false);
	let mut candidate = f.artifact.clone();
	candidate[f.drive_offset..f.drive_offset + 4].copy_from_slice(&0.125f32.to_le_bytes());
	let digest = sha(b"synthetic caller declaration; not a truth certificate");
	let params = hidden::PlanParams {
		scope: hidden::EditScope::SenderDriveAndBias,
		parent_sha256: sha(&f.artifact),
		candidate_sha256: sha(&candidate),
		header_sha256: f.header_sha256.clone(),
		input_sha256: sha(&f.raw),
		allowed_coordinates: vec![
			hidden::Coordinate::Weight { row: 0, column: 0 },
			hidden::Coordinate::Bias { row: 0 },
		],
		edits: vec![
			hidden::Edit {
				coordinate: hidden::Coordinate::Weight { row: 0, column: 0 },
				expected_hex: "00000000".into(),
				replacement_hex: "0000003e".into(),
			},
			hidden::Edit {
				coordinate: hidden::Coordinate::Bias { row: 0 },
				expected_hex: "00000000".into(),
				replacement_hex: "00000000".into(),
			},
		],
		maximum_update_l2_norm: 1.0,
		target_source: hidden::TargetDeclaration {
			kind: hidden::TargetSourceKind::CallerSpecified,
			source_sha256: digest.clone(),
			description: "synthetic byte control".into(),
		},
		identity: Identity {
			code_sha256: digest.clone(),
			tensor_map_sha256: digest.clone(),
			data_manifest_sha256: digest.clone(),
			objective_sha256: digest.clone(),
			dependency_manifest_sha256: digest,
		},
	};
	let plan = hidden::prepare(&params, &f.artifact).unwrap();
	let (bound, evidence) =
		bind_hidden_candidate(&f.profile, &f.artifact, &candidate, &f.raw, &plan).unwrap();
	assert_eq!(
		sender_semantic_map(&bound).unwrap()["artifact_sha256"],
		sha(&candidate)
	);
	assert_eq!(evidence["actual_candidate_verified"], true);
	assert_eq!(evidence["all_other_bytes_preserved"], true);
	assert_eq!(bound.tensors[hidden::WEIGHT_NAME][0], 0.125);
	*candidate.last_mut().unwrap() ^= 1;
	assert!(bind_hidden_candidate(&f.profile, &f.artifact, &candidate, &f.raw, &plan).is_err());
}
