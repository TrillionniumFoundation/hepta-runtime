// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Semantic scope and graph-aware inverse regressions; no training fixture claim.

use super::{
	bound_io::{sha, BoundModel, Inputs},
	late_quote::{self, LateQuoteMinV1},
	trace::ResearchGraph,
};
use serde_json::json;
use std::collections::BTreeMap;

fn fixture(ready: bool) -> (BoundModel, Vec<u8>, Inputs) {
	let mut bytes = vec![0u8; 36 * 4 + 8];
	let mut mark = vec![0.0; 36];
	let mut head = vec![0.0; 40];
	for channel in 0..4 {
		let index = channel * 9 + 7;
		let value: f32 = if ready { -0.25 } else { 0.25 };
		bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
		mark[index] = f64::from(value);
		head[20 + channel * 5 + 2] = 0.5;
	}
	let model = BoundModel {
		tensors: BTreeMap::from([
			("body.input_mark.weight".into(), mark),
			("body.readout.weight".into(), head),
		]),
		source_declarations: json!({}),
		canonical_sha256: sha(&bytes),
		source_checkpoint_sha256: "1".repeat(64),
		profile_identifier: 137,
		artifact_sha256: sha(&bytes),
		header_sha256: "2".repeat(64),
		profile_sha256: "3".repeat(64),
		input_sha256: "4".repeat(64),
		tensor_facts: vec![json!({
			"name":"body.input_mark.weight","file_offset":0,"byte_length":144,"payload_sha256":sha(&bytes[..144])})],
	};
	let mut x = vec![0.0; 108];
	x[97] = -0.25;
	x[106] = 0.25;
	(
		model,
		bytes,
		Inputs {
			n: 1,
			x,
			baseline: vec![0.0; 2],
			labels: vec![0],
		},
	)
}

#[test]
fn compiler_has_no_label_or_output_dependency_and_edits_four_words() {
	let (model, parent, mut inputs) = fixture(false);
	let plan = late_quote::compile(
		&model,
		&parent,
		&LateQuoteMinV1::check(&inputs).unwrap(),
		&"a".repeat(64),
	)
	.unwrap()
	.unwrap();
	inputs.labels[0] = 1;
	let relabeled = late_quote::compile(
		&model,
		&parent,
		&LateQuoteMinV1::check(&inputs).unwrap(),
		&"a".repeat(64),
	)
	.unwrap()
	.unwrap();
	assert_eq!(plan.evidence(), relabeled.evidence());
	assert_eq!(plan.evidence()["changed_f32_words"], 4);
	let original = plan.parent(&parent).unwrap();
	let candidate = plan
		.apply(&original, &LateQuoteMinV1::check(&inputs).unwrap(), true)
		.unwrap();
	for channel in 0..4 {
		let offset = (channel * 9 + 7) * 4;
		assert_eq!(
			&candidate.bytes()[offset..offset + 4],
			&(-0.25f32).to_le_bytes()
		);
	}
	assert_eq!(plan.restore(&candidate, true).unwrap().bytes(), parent);
}

#[test]
fn identical_weight_digest_does_not_mean_the_function_was_restored() {
	let (model, parent, inputs) = fixture(true);
	let plan = late_quote::compile(
		&model,
		&parent,
		&LateQuoteMinV1::check(&inputs).unwrap(),
		&"b".repeat(64),
	)
	.unwrap()
	.unwrap();
	assert_eq!(plan.evidence()["changed_f32_words"], 0);
	let original = plan.parent(&parent).unwrap();
	let candidate = plan
		.apply(&original, &LateQuoteMinV1::check(&inputs).unwrap(), true)
		.unwrap();
	assert_eq!(
		candidate.identity().artifact_sha256,
		original.identity().artifact_sha256
	);
	assert_ne!(candidate.identity(), original.identity());
	assert_ne!(
		candidate.identity().digest().unwrap(),
		original.identity().digest().unwrap()
	);
	assert_eq!(
		candidate.identity().graph,
		ResearchGraph::FinalTickTiedReceiverMark
	);
	assert!(plan
		.apply(&candidate, &LateQuoteMinV1::check(&inputs).unwrap(), true)
		.is_err());
	let restored = plan.restore(&candidate, true).unwrap();
	assert_eq!(restored.identity(), original.identity());
	assert_eq!(restored.bytes(), original.bytes());
}

#[test]
fn semantic_preconditions_reject_missing_price_or_extra_information() {
	for which in 0..5 {
		let (_, _, mut input) = fixture(false);
		match which {
			0 => input.x[0] = 1.0,
			1 => input.x[105] = 1.0,
			2 => input.x[106] = input.x[97],
			3 => input.baseline[1] = 1.0,
			_ => input.x[97] = f32::NAN,
		}
		assert!(LateQuoteMinV1::check(&input).is_err());
	}
}

#[test]
fn inactive_signed_head_abstains_instead_of_manufacturing_a_gain() {
	let (mut model, parent, input) = fixture(false);
	model
		.tensors
		.get_mut("body.readout.weight")
		.unwrap()
		.fill(0.0);
	assert!(late_quote::compile(
		&model,
		&parent,
		&LateQuoteMinV1::check(&input).unwrap(),
		&"c".repeat(64)
	)
	.unwrap()
	.is_none());
}

#[test]
fn prepared_plan_does_not_authorize_another_checked_task() {
	let (model, parent, mut input) = fixture(false);
	let plan = late_quote::compile(
		&model,
		&parent,
		&LateQuoteMinV1::check(&input).unwrap(),
		&"e".repeat(64),
	)
	.unwrap()
	.unwrap();
	let state = plan.parent(&parent).unwrap();
	input.x[97] -= 0.125;
	let other = LateQuoteMinV1::check(&input).unwrap();
	assert!(plan.apply(&state, &other, true).is_err());
}

#[test]
fn candidate_scope_rejects_protected_bytes_and_nonfinite_word() {
	for nonfinite in [false, true] {
		let (model, parent, _) = fixture(false);
		let mut candidate = parent.clone();
		if nonfinite {
			candidate[28..32].copy_from_slice(&f32::NAN.to_le_bytes());
		} else {
			candidate[0] = 1;
		}
		assert!(late_quote::bind_candidate(model, &parent, &candidate).is_err());
	}
}

#[test]
fn measured_goal_gate_keeps_weights_after_goal_without_claiming_perfect_calibration() {
	assert!(late_quote::goal_met(76, 80, 95).unwrap());
	assert!(!late_quote::goal_met(75, 80, 95).unwrap());
	assert!(late_quote::goal_met(81, 80, 95).is_err());
}
