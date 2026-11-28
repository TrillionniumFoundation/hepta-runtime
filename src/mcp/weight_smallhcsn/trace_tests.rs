// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Trace equivalence and explicitly changed late-input graph controls.

use super::{
	bound_io::{BoundModel, Inputs},
	deadline::Deadline,
	model,
	trace::ResearchGraph,
};
use serde_json::json;
use std::{collections::BTreeMap, time::Duration};

fn fixture() -> (BoundModel, Inputs) {
	let mut tensors = BTreeMap::new();
	for (name, length) in [
		("body.raw_cost", 8),
		("body.raw_boundary", 8),
		("body.input_drive.weight", 36),
		("body.input_drive.bias", 4),
		("body.input_mark.weight", 36),
		("body.input_mark.bias", 4),
		("body.recurrent.weight", 192),
		("body.readout.weight", 40),
		("body.readout.bias", 2),
	] {
		tensors.insert(name.to_owned(), vec![0.0; length]);
	}
	tensors.insert("body.fixed_boundary".into(), vec![-0.5; 8]);
	tensors.insert("body.reset_absolute".into(), vec![0.5; 8]);
	tensors.insert("body.synaptic_mask".into(), vec![1.0; 192]);
	for sender in 0..4 {
		tensors.get_mut("body.input_drive.weight").unwrap()[sender * 9 + 7] = 0.125;
		tensors.get_mut("body.input_mark.weight").unwrap()[sender * 9 + 7] = 0.25;
		tensors.get_mut("body.recurrent.weight").unwrap()[(sender + 4) * 24 + sender] = 0.125;
		tensors.get_mut("body.readout.weight").unwrap()[20 + sender * 5 + 2] = 0.25;
	}
	let model = BoundModel {
		tensors,
		source_declarations: json!({}),
		canonical_sha256: "0".repeat(64),
		source_checkpoint_sha256: "1".repeat(64),
		profile_identifier: 1,
		artifact_sha256: "0".repeat(64),
		header_sha256: "2".repeat(64),
		profile_sha256: "3".repeat(64),
		input_sha256: "4".repeat(64),
		tensor_facts: vec![],
	};
	let inputs = Inputs {
		n: 2,
		x: (0..216).map(|i| (i % 13) as f32 * 0.015625).collect(),
		baseline: vec![0.125, -0.25, 0.25, -0.125],
		labels: vec![0, 1],
	};
	(model, inputs)
}

#[test]
fn observations_preserve_all_original_output_bytes() {
	let (model, inputs) = fixture();
	let deadline = Deadline::new(Duration::from_secs(20));
	let original = model::evaluate(&model, &inputs, &deadline).unwrap();
	let (observed, trace) = model::evaluate_traced(&model, &inputs, &deadline).unwrap();
	assert_eq!(original.bytes(), observed.bytes());
	assert_eq!(trace.len(), inputs.n * 12);
	for row in trace.iter().filter(|row| row.tick == 5) {
		assert_eq!(
			row.choice_score.to_bits(),
			original.scores[row.query * 2 + row.choice].to_bits()
		);
	}
}

#[test]
fn local_signed_rate_affine_matches_actual_flow_with_rounding_tolerance() {
	let (model, inputs) = fixture();
	let (_, trace) =
		model::evaluate_traced(&model, &inputs, &Deadline::new(Duration::from_secs(20))).unwrap();
	for row in trace {
		for neuron in 0..8 {
			assert!(row.signed_rate_mark_slope[neuron] >= 0.0);
			let actual = f64::from(row.features[neuron][2]);
			let predicted = row.signed_rate_mark_offset[neuron]
				+ row.signed_rate_mark_slope[neuron] * f64::from(row.raw_mark[neuron].tanh());
			assert!((actual - predicted).abs() <= 2e-7 * (1.0 + actual.abs()));
		}
	}
}

#[test]
fn final_tick_graph_adds_mark_path_and_preserves_probability_features() {
	let (model, mut inputs) = fixture();
	let deadline = Deadline::new(Duration::from_secs(20));
	let original = model::evaluate(&model, &inputs, &deadline).unwrap();
	for query in 0..2 {
		for choice in 0..2 {
			inputs.x[((query * 6 + 5) * 2 + choice) * 9 + 7] +=
				if choice == 0 { -0.5 } else { 0.5 };
		}
	}
	let changed_input = model::evaluate(&model, &inputs, &deadline).unwrap();
	assert_eq!(original.bytes(), changed_input.bytes());
	let (bridged, _) = model::evaluate_research_traced(
		&model,
		&inputs,
		&deadline,
		ResearchGraph::FinalTickTiedReceiverMark,
	)
	.unwrap();
	assert_ne!(changed_input.scores, bridged.scores);
	for (index, (a, b)) in changed_input
		.features
		.iter()
		.zip(&bridged.features)
		.enumerate()
	{
		if index % 5 != 2 {
			assert_eq!(a.to_bits(), b.to_bits());
		}
	}
}

#[test]
fn expired_observation_does_not_return_partial_trace() {
	let (model, inputs) = fixture();
	assert!(model::evaluate_traced(&model, &inputs, &Deadline::new(Duration::ZERO)).is_err());
}
