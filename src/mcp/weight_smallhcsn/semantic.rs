// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Source-bound static roles for the one fixed kernel; no intervention or forward runs here.

use super::{bound_io::BoundModel, sha};
use anyhow::{bail, Result};
use serde_json::{json, Value};

fn role(name: &str) -> Result<(&'static str, bool)> {
	Ok(match name {
		"body.input_drive.weight" | "body.input_drive.bias" => {
			("sender_drive_and_cost_preactivation", true)
		}
		"body.input_mark.weight" | "body.input_mark.bias" => {
			("sender_signed_mark_preactivation", false)
		}
		"body.recurrent.weight" => ("masked_centered_boundary_messages", false),
		"body.synaptic_mask" => ("fixed_recurrent_coordinate_mask", false),
		"body.raw_cost" => ("qvi_cost_offset", false),
		"body.raw_boundary" => ("inactive_in_this_fixed_qvi_branch", false),
		"body.fixed_boundary" => ("initial_and_message_centering_boundary", false),
		"body.reset_absolute" => ("absolute_reset_and_qvi_reset_target", false),
		"body.readout.weight" | "body.readout.bias" => ("fixed_two_raw_head_outputs", false),
		_ => bail!("semantic map encountered an unsupported fixed-profile tensor"),
	})
}

/// Coordinates classified here are structurally eligible in this fixed program.
/// This is not measured causal influence on a particular batch or a profit estimate.
pub fn sender_semantic_map(model: &BoundModel) -> Result<Value> {
	let mut tensors = Vec::new();
	for fact in &model.tensor_facts {
		let name = fact["name"]
			.as_str()
			.ok_or_else(|| anyhow::anyhow!("bound tensor name"))?;
		let (role, editable) = role(name)?;
		let mut item = fact.clone();
		item["role"] = json!(role);
		item["sender_edit_scope"] = json!(editable);
		item["protected_in_sender_scope"] = json!(!editable);
		if matches!(name, "body.input_mark.weight" | "body.input_mark.bias") {
			item["structural_score_path"] = json!(false);
			item["state_effect"] = json!("sender signed-mark state and diagnostics may change; boundary-only messages and receiver-only readout carry no sender-mark path to completed scores");
		}
		tensors.push(item);
	}
	let mask = &model.tensors["body.synaptic_mask"];
	let mut active = Vec::new();
	let mut inactive = Vec::new();
	for row in 0..8 {
		for column in 0..24 {
			let index = row * 24 + column;
			if column < 8 && mask[index] != 0.0 {
				active.push(index);
			} else {
				inactive.push(index);
			}
		}
	}
	let groups: Vec<_> = (4..8).map(|neuron| json!({
		"receiver_neuron":neuron,"feature_begin":(neuron-4)*5,"feature_end_exclusive":(neuron-3)*5,
		"features":["analytic_continuation_value","first_passage_risk","signed_event_rate","event_rate","normalized_margin"]
	})).collect();
	let implementation = super::evaluator_identity();
	let mut map = json!({
		"schema":"hepta.smallhcsn.sender-semantic-map.v1",
		"profile":"centered_boundary_qvi_mixed_six_tick_sender40",
		"artifact_sha256":model.artifact_sha256,"header_sha256":model.header_sha256,
		"profile_bytes_sha256":model.profile_sha256,"raw_input_sha256":model.input_sha256,
		"implementation_sha256":implementation,"tensors":tensors,
		"allowed_parameters":{"weight_tensor":"body.input_drive.weight","weight_shape":[4,9],"bias_tensor":"body.input_drive.bias","bias_shape":[4],"maximum_coordinates":40},
		"protected_tensor_count":10,"sender_policy_requires_header_aliases_and_all_other_bytes_protected":true,
		"recurrent":{"stored_elements":192,"program_selected_columns":[0,1,2,3,4,5,6,7],"program_selected_elements_before_mask":64,
			"potentially_active_elements":active.len(),"inert_elements":inactive.len(),
			"potentially_active_indices":active,"inert_indices":inactive,
			"classification":"program selection and captured fixed mask; no causal intervention executed"},
		"feature_groups":groups,"feature_count":20,
		"execution":{"queries_maximum":80,"choices":2,"ticks":6,"qvi_refresh_ticks_zero_based":[0,2,4],
			"message":"prior boundary minus fixed nominal boundary; zero at first tick",
			"sender_drive_effects":["drift","cost","qvi_boundary","future_centered_messages"],
			"raw_head_order":["head_0","head_1"],"choice_score":"F32(normalized_external_baseline + F32(head_1 - head_0))",
			"classification":"choice_1 only when score_1 > score_0; ties select choice_0"},
		"named_capability_limits":{"analytic_first_passage_and_reset":true,"analytic_continuation_value":true,
			"call_put_head_semantics_verified":false,"belief_head_verified":false,"learned_continuation_q_head_verified":false,"ndu_controller_present":false},
		"declared_source_provenance_independently_verified":false,"target_truth_verified":false,
		"owner_authority_granted_by_this_pure_map":false,"full_model_executed":false,"model_calls":0,"weight_writes":0
	});
	let digest = sha(&serde_json::to_vec(&map)?);
	map["semantic_map_sha256"] = json!(digest);
	Ok(map)
}
