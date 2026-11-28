// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Positive, malformed-program and exact-budget controls for pure composition.
//! Synthetic fixtures test software behavior; the ignored private-input runner
//! does not authenticate checkpoint files or establish model quality.

use super::*;

fn hex(value: f32) -> String {
	value
		.to_le_bytes()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect()
}

fn edit(index: u64, before: f32, after: f32) -> ExactElementEdit {
	ExactElementEdit {
		index,
		expected_hex: hex(before),
		replacement_hex: hex(after),
	}
}

fn tensor(name: &str, elements: u64, radius: f64) -> TensorContract {
	TensorContract {
		name: name.into(),
		dtype: "F32".into(),
		layout: "row_major_le".into(),
		shape: vec![elements],
		source_tensor_sha256: sha256(format!("synthetic-tensor:{name}").as_bytes()),
		protected: false,
		maximum_update_l2_norm: radius,
	}
}

fn request(tensors: Vec<TensorContract>, radius: f64) -> Request {
	Request {
		schema: SCHEMA.into(),
		binding: Binding {
			base_checkpoint_sha256: sha256(b"synthetic-checkpoint"),
			model_graph_sha256: sha256(b"synthetic-model-graph"),
			tensor_map_sha256: tensor_map_sha256(&tensors).unwrap(),
			semantics_sha256: sha256(b"synthetic-endpoint-semantics"),
			row_protocol_sha256: sha256(b"synthetic-rows-protocol"),
			objective_sha256: sha256(b"synthetic-objective"),
			dependency_manifest_sha256: sha256(b"synthetic-dependencies"),
		},
		tensors,
		maximum_update_l2_norm: radius,
		steps: Vec::new(),
	}
}

fn append(request: &mut Request, name: &str, edits: Vec<ExactElementEdit>) {
	request.steps.push(Step {
		step_id: sha256(format!("synthetic-step:{}", request.steps.len()).as_bytes()),
		binding: request.binding.clone(),
		members: vec![TensorStep {
			tensor_name: name.into(),
			edits,
		}],
	});
}

fn fixture() -> Request {
	let mut result = request(vec![tensor("continuation.weight", 147, 4.0)], 4.0);
	append(&mut result, "continuation.weight", vec![edit(0, 0.0, 0.25)]);
	append(&mut result, "continuation.weight", vec![edit(0, 0.25, 0.5)]);
	result
}

fn rejects(request: &Request, expected: &str) {
	let before = serde_json::to_vec(request).unwrap();
	let error = compose(request).unwrap_err().to_string();
	assert!(error.contains(expected), "unexpected error: {error}");
	assert_eq!(serde_json::to_vec(request).unwrap(), before);
}

#[test]
fn repeated_coordinate_retains_original_anchor_and_every_step() {
	let request = fixture();
	let before = serde_json::to_vec(&request).unwrap();
	let plan = compose(&request).unwrap();
	assert_eq!(plan.total_step_edits, 2);
	assert_eq!(plan.union_elements, 1);
	assert_eq!(plan.changed_elements, 1);
	assert_eq!(plan.cancelled_elements, 0);
	assert_eq!(plan.members[0].edits[0].expected_hex, hex(0.0));
	assert_eq!(plan.members[0].edits[0].replacement_hex, hex(0.5));
	assert_eq!(plan.members[0].history[0].changes.len(), 2);
	assert_eq!(
		plan.members[0].history[0].changes[0].replacement_hex,
		hex(0.25)
	);
	assert_eq!(
		plan.members[0].history[0].changes[1].expected_hex,
		hex(0.25)
	);
	assert_eq!(plan.net_update_budget["elements_checked"], 1);
	assert_eq!(serde_json::to_vec(&request).unwrap(), before);
	assert_eq!(
		serde_json::to_vec(&plan).unwrap(),
		serde_json::to_vec(&compose(&request).unwrap()).unwrap()
	);
}

#[test]
fn individually_small_steps_cannot_evade_the_original_global_radius() {
	let mut request = request(vec![tensor("a", 1, 2.0)], 1.0);
	append(&mut request, "a", vec![edit(0, 0.0, 0.75)]);
	append(&mut request, "a", vec![edit(0, 0.75, 1.5)]);
	assert!(
		weight_norm::check_pairs([(0.0, 0.75)], 1.0)
			.unwrap()
			.within_budget
	);
	assert!(
		weight_norm::check_pairs([(0.75, 1.5)], 1.0)
			.unwrap()
			.within_budget
	);
	rejects(&request, "global radius from the original anchor");
}

#[test]
fn cancellation_is_retained_and_checked_by_net_not_path_distance() {
	let mut request = request(vec![tensor("a", 1, 0.0)], 0.0);
	append(&mut request, "a", vec![edit(0, 1.0, 2.0)]);
	append(&mut request, "a", vec![edit(0, 2.0, 1.0)]);
	let plan = compose(&request).unwrap();
	assert_eq!(plan.changed_elements, 0);
	assert_eq!(plan.cancelled_elements, 1);
	assert_eq!(plan.union_elements, 1);
	assert_eq!(plan.total_step_edits, 2);
	assert_eq!(plan.members[0].edits.len(), 1);
	assert_eq!(plan.members[0].edits[0].expected_hex, hex(1.0));
	assert_eq!(plan.members[0].edits[0].replacement_hex, hex(1.0));
	assert_eq!(plan.members[0].history[0].changes.len(), 2);
	assert_eq!(plan.net_update_budget["squared_update_units_hex"], "0");
	assert!(!plan.intermediate_models_executed);
}

#[test]
fn signed_zero_byte_change_has_zero_numeric_radius() {
	let mut request = request(vec![tensor("a", 1, 0.0)], 0.0);
	append(&mut request, "a", vec![edit(0, 0.0, -0.0)]);
	let plan = compose(&request).unwrap();
	assert_eq!(plan.changed_elements, 1);
	assert_eq!(plan.members[0].edits[0].replacement_hex, "00000080");
	assert_eq!(plan.net_update_budget["squared_update_units_hex"], "0");
}

#[test]
fn exact_noop_preserves_old_bytes_and_does_not_disappear() {
	let mut request = request(vec![tensor("a", 1, 0.0)], 0.0);
	append(&mut request, "a", vec![edit(0, 3.0, 3.0)]);
	let plan = compose(&request).unwrap();
	assert_eq!(plan.union_elements, 1);
	assert_eq!(plan.changed_elements, 0);
	assert_eq!(plan.cancelled_elements, 0);
	assert_eq!(plan.members[0].edits.len(), 1);
	assert_eq!(plan.members[0].history[0].changes.len(), 1);
}

#[test]
fn exact_radius_checks_the_stored_f32_not_the_unrounded_decimal() {
	let mut request = request(vec![tensor("a", 1, 1.0)], 0.1);
	append(&mut request, "a", vec![edit(0, 0.0, 0.1)]);
	rejects(&request, "global radius from the original anchor");
	request.maximum_update_l2_norm = f64::from(0.1_f32);
	assert!(compose(&request).unwrap().net_update_budget["within_budget"] == true);
}

#[test]
fn subnormal_radius_boundary_is_exact() {
	let subnormal = f32::from_bits(1);
	let radius = f64::from(subnormal);
	let mut request = request(vec![tensor("a", 1, radius)], radius);
	append(&mut request, "a", vec![edit(0, 0.0, subnormal)]);
	assert!(compose(&request).is_ok());
	request.maximum_update_l2_norm = f64::from_bits(radius.to_bits() - 1);
	rejects(&request, "global radius from the original anchor");
}

#[test]
fn largest_finite_f32_difference_uses_existing_exact_norm() {
	let mut request = request(vec![tensor("a", 1, f64::MAX)], f64::MAX);
	append(&mut request, "a", vec![edit(0, f32::MAX, -f32::MAX)]);
	let plan = compose(&request).unwrap();
	assert_eq!(plan.net_update_budget["within_budget"], true);
	assert_eq!(plan.changed_elements, 1);
}

#[test]
fn member_and_joint_radius_are_both_enforced() {
	let mut request = request(vec![tensor("a", 1, 0.5), tensor("b", 1, 1.0)], 2.0);
	append(&mut request, "a", vec![edit(0, 0.0, 0.75)]);
	request.steps[0].members.push(TensorStep {
		tensor_name: "b".into(),
		edits: vec![edit(0, 0.0, 0.75)],
	});
	rejects(&request, "member exceeds its exact radius");
	request.tensors[0].maximum_update_l2_norm = 1.0;
	request.maximum_update_l2_norm = 1.0;
	rejects(&request, "global radius from the original anchor");
	request.maximum_update_l2_norm = 2.0;
	let plan = compose(&request).unwrap();
	assert_eq!(plan.members.len(), 2);
	assert_eq!(plan.net_update_budget["elements_checked"], 2);
}

#[test]
fn discontinuous_old_bytes_are_rejected_without_mutating_input() {
	let mut request = fixture();
	request.steps[1].members[0].edits[0].expected_hex = hex(0.0);
	rejects(&request, "discontinuous old/new bytes");
}

#[test]
fn every_anchor_and_semantic_binding_is_checked_on_every_step() {
	for field in 0..7 {
		let mut request = fixture();
		let binding = &mut request.steps[1].binding;
		let different = sha256(b"different identity");
		match field {
			0 => binding.base_checkpoint_sha256 = different,
			1 => binding.model_graph_sha256 = different,
			2 => binding.tensor_map_sha256 = different,
			3 => binding.semantics_sha256 = different,
			4 => binding.row_protocol_sha256 = different,
			5 => binding.objective_sha256 = different,
			6 => binding.dependency_manifest_sha256 = different,
			_ => unreachable!(),
		}
		rejects(&request, "step binding differs");
	}
}

#[test]
fn tensor_shape_source_and_map_drift_are_rejected() {
	let mut request = fixture();
	request.tensors[0].shape = vec![49, 3];
	rejects(&request, "tensor descriptor map differs");
	request = fixture();
	request.tensors[0].source_tensor_sha256 = sha256(b"different tensor bytes");
	rejects(&request, "tensor descriptor map differs");
	request = fixture();
	request.binding.tensor_map_sha256 = sha256(b"unrelated map");
	rejects(&request, "tensor descriptor map differs");
}

#[test]
fn dtype_layout_and_invalid_shapes_are_rejected() {
	let mut request = fixture();
	request.tensors[0].dtype = "BF16".into();
	rejects(&request, "invalid F32 tensor");
	request = fixture();
	request.tensors[0].layout = "column_major_le".into();
	rejects(&request, "invalid F32 tensor");
	for shape in [
		vec![],
		vec![0],
		vec![u64::MAX],
		vec![2, u64::MAX],
		vec![1; 9],
		vec![1024, 1025],
	] {
		request = fixture();
		request.tensors[0].shape = shape;
		assert!(compose(&request).is_err());
	}
}

#[test]
fn duplicate_step_tensor_and_coordinate_identities_are_rejected() {
	let mut request = fixture();
	request.steps[1].step_id = request.steps[0].step_id.clone();
	rejects(&request, "step identity must be unique");
	request = fixture();
	let duplicate_member = request.steps[0].members[0].clone();
	request.steps[0].members.push(duplicate_member);
	rejects(&request, "duplicate tensor member");
	request = fixture();
	request.steps[0].members[0].edits.push(edit(0, 0.25, 0.5));
	rejects(&request, "duplicate or out-of-range coordinate");
	request = fixture();
	let duplicate_tensor = request.tensors[0].clone();
	request.tensors.push(duplicate_tensor);
	rejects(&request, "duplicate tensor contract");
}

#[test]
fn unknown_tensor_out_of_range_and_protected_noop_are_rejected() {
	let mut request = fixture();
	request.steps[0].members[0].tensor_name = "unknown".into();
	rejects(&request, "undeclared tensor");
	request = fixture();
	request.steps[0].members[0].edits[0].index = 147;
	rejects(&request, "out-of-range coordinate");
	request = fixture();
	request.tensors[0].protected = true;
	request.steps[0].members[0].edits[0].replacement_hex = hex(0.0);
	rejects(&request, "protected tensor");
}

#[test]
fn nonfinite_intermediate_bytes_and_malformed_hex_are_rejected() {
	for bytes in ["0000807f", "000080ff", "0000c07f"] {
		let mut request = fixture();
		request.steps[0].members[0].edits[0].replacement_hex = bytes.into();
		request.steps[1].members[0].edits[0].expected_hex = bytes.into();
		rejects(&request, "finite intermediate");
	}
	for bytes in ["", "00", "0000803F", "gggggggg", "0000000000"] {
		let mut request = fixture();
		request.steps[0].members[0].edits[0].expected_hex = bytes.into();
		assert!(compose(&request).is_err());
	}
}

#[test]
fn invalid_hash_radius_empty_program_and_unknown_fields_are_rejected() {
	let mut request = fixture();
	request.binding.base_checkpoint_sha256 = "ab".into();
	rejects(&request, "complete lowercase SHA-256");
	for radius in [f64::NAN, f64::INFINITY, -1.0] {
		request = fixture();
		request.maximum_update_l2_norm = radius;
		assert!(compose(&request).is_err());
	}
	request = fixture();
	request.steps.clear();
	rejects(&request, "1 to 64 steps");
	let mut json = serde_json::to_value(fixture()).unwrap();
	json["holdout_verified"] = Value::Bool(true);
	assert!(serde_json::from_value::<Request>(json).is_err());
}

#[test]
fn union_limit_is_global_and_keeps_cancelled_coordinates_counted() {
	let mut request = request(vec![tensor("a", 2048, 32.0)], 32.0);
	append(
		&mut request,
		"a",
		(0..1024).map(|i| edit(i, 0.0, 0.5)).collect(),
	);
	assert_eq!(compose(&request).unwrap().union_elements, 1024);
	append(
		&mut request,
		"a",
		(0..1024).map(|i| edit(i, 0.5, 0.0)).collect(),
	);
	request.maximum_update_l2_norm = 1.0;
	assert_eq!(compose(&request).unwrap().cancelled_elements, 1024);
	append(&mut request, "a", vec![edit(1024, 0.0, 0.5)]);
	rejects(&request, "touched-coordinate union exceeds 1024");
	let mut cross_tensor = fixture();
	cross_tensor.tensors = vec![tensor("a", 1024, 32.0), tensor("b", 1, 32.0)];
	cross_tensor.binding.tensor_map_sha256 = tensor_map_sha256(&cross_tensor.tensors).unwrap();
	cross_tensor.maximum_update_l2_norm = 32.0;
	cross_tensor.steps.clear();
	append(
		&mut cross_tensor,
		"a",
		(0..1024).map(|i| edit(i, 0.0, 0.5)).collect(),
	);
	append(&mut cross_tensor, "b", vec![edit(0, 0.0, 0.5)]);
	rejects(&cross_tensor, "touched-coordinate union exceeds 1024");
}

#[test]
fn program_operation_budget_counts_repeated_noops() {
	let mut request = request(vec![tensor("a", 1024, 0.0)], 0.0);
	for _ in 0..4 {
		append(
			&mut request,
			"a",
			(0..1024).map(|i| edit(i, 0.0, 0.0)).collect(),
		);
	}
	assert_eq!(compose(&request).unwrap().total_step_edits, 4096);
	append(&mut request, "a", vec![edit(0, 0.0, 0.0)]);
	rejects(&request, "4096-operation program budget");
}

#[test]
fn step_limit_counts_even_exact_noops() {
	let mut request = request(vec![tensor("a", 1, 0.0)], 0.0);
	for _ in 0..64 {
		append(&mut request, "a", vec![edit(0, 0.0, 0.0)]);
	}
	assert_eq!(compose(&request).unwrap().steps.len(), 64);
	append(&mut request, "a", vec![edit(0, 0.0, 0.0)]);
	rejects(&request, "1 to 64 steps");
}

#[test]
fn canonical_serialization_has_an_actual_bounded_writer() {
	let tensors: Vec<_> = (0..32)
		.map(|i| tensor(&format!("{i:02}{}", "a".repeat(4094)), 1, 0.0))
		.collect();
	let mut request = request(tensors, 0.0);
	for i in 0..8 {
		request.steps.push(Step {
			step_id: sha256(format!("large-step:{i}").as_bytes()),
			binding: request.binding.clone(),
			members: request
				.tensors
				.iter()
				.map(|t| TensorStep {
					tensor_name: t.name.clone(),
					edits: vec![edit(0, 0.0, 0.0)],
				})
				.collect(),
		});
	}
	rejects(&request, "composition serialization budget exceeded");
}

#[test]
fn tensor_map_is_canonical_but_complete_program_keeps_policy_changes() {
	let tensors = vec![tensor("b", 1, 1.0), tensor("a", 1, 1.0)];
	let mut reversed = tensors.clone();
	reversed.reverse();
	assert_eq!(
		tensor_map_sha256(&tensors).unwrap(),
		tensor_map_sha256(&reversed).unwrap()
	);
	let mut request = fixture();
	let first = compose(&request).unwrap().program_sha256;
	request.maximum_update_l2_norm = 5.0;
	assert_ne!(first, compose(&request).unwrap().program_sha256);
}

#[test]
fn output_never_claims_source_holdout_execution_or_adoption_authority() {
	let plan = compose(&fixture()).unwrap();
	assert!(!plan.source_authenticated);
	assert!(!plan.independent_holdout_verified);
	assert!(!plan.cross_request_budget_enforced);
	assert!(!plan.intermediate_models_executed);
	assert!(!plan.weights_modified);
	assert!(!plan.production_eligible);
}

#[test]
#[ignore = "requires an explicitly pinned private program and an absent output file"]
fn external_private_program() {
	let input = std::env::var("HEPTA_COMPOSITION_REQUEST").unwrap();
	let expected = std::env::var("HEPTA_COMPOSITION_REQUEST_SHA256").unwrap();
	let output = std::env::var("HEPTA_COMPOSITION_OUTPUT").unwrap();
	assert!(valid_sha256(&expected));
	let bytes = std::fs::read(input).unwrap();
	assert!(bytes.len() <= MAX_REQUEST_BYTES);
	assert_eq!(sha256(&bytes), expected);
	let request: Request = serde_json::from_slice(&bytes).unwrap();
	let plan = compose(&request).unwrap();
	let result = serde_json::to_vec_pretty(&plan).unwrap();
	let mut options = std::fs::OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	let mut file = options.open(output).unwrap();
	file.write_all(&result).unwrap();
	file.sync_all().unwrap();
	println!(
		"WEIGHT_COMPOSITION_RESEARCH program={} coordinates={} operations={} source_authenticated=false weights_modified=false",
		plan.program_sha256, plan.union_elements, plan.total_step_edits
	);
}
