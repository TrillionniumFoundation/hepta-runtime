// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Five fixed sufficient heads; only the existing canonical owner publishes edits.

use super::*;
use crate::sufficient_source::{self, ACCEPTANCE_SHA, FITS, ROLE};

pub fn prepare(queue_path: &Path, queue_sha: &str, output: &Path) -> Result<()> {
	let queue = verified(queue_path, queue_sha)?;
	std::fs::create_dir(output)?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o700))?;
	}
	let mut cases = Vec::new();
	for fit in FITS {
		let source = sufficient_source::load(queue.clone(), fit)?;
		let (original_json, intent, review) = sufficient_source::review(&source)?;
		let original_model = unique_json(&original_json)?;
		let original_bridge = codec::encode(&original_json)?;
		let expected_candidate = codec::edit(&original_bridge, &digest(&original_bridge), &intent)?;
		let candidate_model = unique_json(&codec::decode(&expected_candidate)?)?;
		let root = output.join(format!("fit_{fit}"));
		std::fs::create_dir(&root)?;
		let original_path = root.join("original.safetensors");
		let json_path = root.join("original.json");
		let candidate_path = root.join("expected-candidate.safetensors");
		raw_new(&original_path, &original_bridge)?;
		raw_new(&json_path, &original_json)?;
		raw_new(&candidate_path, &expected_candidate)?;
		let edits = intent
			.edits
			.iter()
			.enumerate()
			.map(|(index, e)| {
				let hex =
					|bytes: &[u8]| bytes.iter().map(|v| format!("{v:02x}")).collect::<String>();
				Ok(
					json!({"index":index,"expected_hex":hex(&bits(&e.old_bits)?.to_le_bytes()),
				"replacement_hex":hex(&bits(&e.new_bits)?.to_le_bytes())}),
				)
			})
			.collect::<Result<Vec<_>>>()?;
		let manifest = json!({"schema":"hepta.sufficient-canonical-owner-case.v1","fit":fit,
			"candidate_id":format!("SUFFICIENT_QB_{fit}"),"queue":file_pin(queue_path)?,
			"helper":file_pin(&std::env::current_exe()?)?,"original_bridge":file_pin(&original_path)?,
			"original_json":file_pin(&json_path)?,"expected_candidate":file_pin(&candidate_path)?,
			"original_weights_sha256":codec::weights_hash(&original_model)?,
			"candidate_weights_sha256":codec::weights_hash(&candidate_model)?,
			"protected_fields_sha256":codec::protected_hash(&original_model)?,"adapter_review":review,
			"patch":{"path":original_path,"expected_sha256":digest(&original_bridge),"tensor_name":"readout196","edits":edits},
			"arithmetic":forward::ARITHMETIC,"hardware_key":queue["hardware_key"],
			"full_state_reference":source.entry["reference"],"sealed_head":source.entry["sealed_head"],
			"value_acceptance_sha256":ACCEPTANCE_SHA,"role":ROLE,"source_model":source.original,
			"production_admission":false,"new_candidate_search":false,"independent_confirmation":false});
		let case_path = root.join("CASE.json");
		write_new(&case_path, &manifest)?;
		cases.push(
			json!({"fit":fit,"candidate_id":format!("SUFFICIENT_QB_{fit}"),"case":file_pin(&case_path)?}),
		);
	}
	write_new(
		&output.join("OWNER_QUEUE.json"),
		&json!({"schema":"hepta.sufficient-canonical-owner-queue.v1",
		"source_queue":file_pin(queue_path)?,"cases":cases,"value_acceptance_sha256":ACCEPTANCE_SHA,
		"production_admission":false,"new_candidate_search":false,"role":ROLE,
		"work":{"fixed_heads_materialized":5,"full_policy_DPs":0,"new_parameter_proposals":0,
		"training_steps":0,"canonical_owner_calls":0}}),
	)?;
	Ok(())
}

pub fn evaluate(
	case_path: &Path,
	case_sha: &str,
	artifact: &Path,
	output: &Path,
	restore: bool,
) -> Result<()> {
	let start = Instant::now();
	let case = verified(case_path, case_sha)?;
	let fit = case["fit"].as_u64().ok_or_else(|| anyhow!("fit missing"))?;
	if case["schema"] != "hepta.sufficient-canonical-owner-case.v1"
		|| !FITS.contains(&fit)
		|| case["candidate_id"] != format!("SUFFICIENT_QB_{fit}")
		|| case["arithmetic"] != forward::ARITHMETIC
		|| case["role"] != ROLE
		|| case["value_acceptance_sha256"] != ACCEPTANCE_SHA
		|| case["production_admission"] != false
		|| case["new_candidate_search"] != false
	{
		bail!("sufficient private case contract differs");
	}
	if pinned(&case["helper"])? != bounded(&std::env::current_exe()?)? {
		bail!("sufficient helper binary identity differs");
	}
	let original = pinned(&case["original_bridge"])?;
	let original_json = pinned(&case["original_json"])?;
	if codec::decode(&original)? != original_json {
		bail!("original F64 bridge did not preserve JSON bytes");
	}
	let actual = bounded(artifact)?;
	let actual_json = codec::decode(&actual)?;
	let model = unique_json(&actual_json)?;
	let expected = if restore {
		original
	} else {
		pinned(&case["expected_candidate"])?
	};
	let weight_key = if restore {
		"original_weights_sha256"
	} else {
		"candidate_weights_sha256"
	};
	if actual != expected
		|| codec::weights_hash(&model)? != case[weight_key]
		|| codec::protected_hash(&model)? != case["protected_fields_sha256"]
	{
		bail!("canonical artifact differs from the exact fixed head or protected fields");
	}
	if restore {
		if actual_json != original_json {
			bail!("restored original JSON bytes differ");
		}
		write_new(
			output,
			&json!({"schema":"hepta.sufficient-owner-native-restore.v1","status":"PASS",
			"fit":fit,"candidate_id":case["candidate_id"],"artifact_sha256":digest(&actual),
			"restored_JSON_sha256":digest(&actual_json),"weights_sha256":codec::weights_hash(&model)?,
			"full_policy_DPs":0,"original_bytes_exact":true,"production_eligible":false,
			"wall_seconds":start.elapsed().as_secs_f64()}),
		)?;
		return Ok(());
	}
	let source = sufficient_source::load(unique_json(&pinned(&case["queue"])?)?, fit)?;
	if source.queue["hardware_key"] != case["hardware_key"]
		|| source.entry["reference"] != case["full_state_reference"]
		|| source.entry["sealed_head"] != case["sealed_head"]
	{
		bail!("hardware/state/sealed-head reference identity differs");
	}
	let authenticated = authenticate_source(
		&source.compressed,
		&source.compressed_pin,
		&source.decoded_pin,
		&source.profile,
	)?;
	let reference = unique_json(&pinned(&source.entry["reference"])?)?;
	if reference["schema"] != "hepta.sufficient-native-reference.v1"
		|| reference["fit"] != fit
		|| reference["role"] != ROLE
		|| reference["source_job"] != source.entry["source_job"]
		|| reference["sealed_head"] != source.entry["sealed_head"]
	{
		bail!("new sufficient reference identity differs");
	}
	let public: task::Public = serde_json::from_value(reference["graph"]["public"].clone())?;
	let hardware = source.queue["hardware_key"]
		.as_str()
		.ok_or_else(|| anyhow!("hardware key"))?;
	write_new(
		&output.with_extension("DAG_STARTED.json"),
		&json!({"fit":fit,"reserved_policy_DPs":1,
		"attempted_full_native_DAGs":1,"attempted_policy_DPs":0,"verified_policy_DPs":0}),
	)?;
	let graph = dag::build(&authenticated, &model, &public, hardware)?;
	let graph_check = compare::graph(&graph, &reference)?;
	write_new(
		&output.with_extension("DP_STARTED.json"),
		&json!({"fit":fit,"reserved_policy_DPs":1,
		"attempted_policy_DPs":1,"verified_policy_DPs":0,"actual_completed_policy_DPs":null}),
	)?;
	let evaluation = dag::evaluate(&graph, &codec::readout(&model)?)?;
	write_new(
		&output.with_extension("DP_COMPLETED.json"),
		&json!({"fit":fit,
		"attempted_policy_DPs":1,"actual_completed_policy_DPs":1,"verified_policy_DPs":0}),
	)?;
	let policy_check = compare::policy(&evaluation, &reference["policy"])?;
	let targets = reference["target_events"]
		.as_array()
		.ok_or_else(|| anyhow!("target events"))?;
	if targets.len() as u64
		!= source.entry["source_job"]["events"]
			.as_u64()
			.ok_or_else(|| anyhow!("event count"))?
	{
		bail!("fixed target count differs");
	}
	for event in targets {
		let state = event["state"]
			.as_u64()
			.ok_or_else(|| anyhow!("target state"))? as usize;
		let action = event["target_action"]
			.as_u64()
			.ok_or_else(|| anyhow!("target action"))? as usize;
		if state >= graph.states.len()
			|| action >= 6
			|| evaluation.actions[state] != action
			|| !graph.masks[state][action]
			|| (0..6).any(|other| {
				other != action
					&& graph.masks[state][other]
					&& evaluation.scores[state][other] >= evaluation.scores[state][action]
			}) {
			bail!("native fixed target is not uniquely selected");
		}
	}
	authenticated.verify_unchanged(&bounded(&source.source_path)?)?;
	write_new(
		output,
		&json!({"schema":"hepta.sufficient-owner-native-evaluation.v1","status":"PASS",
		"fit":fit,"candidate_id":case["candidate_id"],"case_sha256":case_sha,
		"artifact_sha256":digest(&actual),"weights_sha256":codec::weights_hash(&model)?,
		"graph":graph_check,"policy":policy_check,"full_native_DAGs":1,"full_policy_DPs":1,
		"reserved_policy_DPs":1,"attempted_policy_DPs":1,"verified_policy_DPs":1,
		"all_fixed_targets_uniquely_matched":true,"fixed_target_count":targets.len(),
		"eligible_for_production_adoption":false,"new_quality_comparison":false,
		"NumPy_exp_certificate_transferred_to_Rust":false,"role":ROLE,
		"wall_seconds":start.elapsed().as_secs_f64()}),
	)?;
	Ok(())
}
