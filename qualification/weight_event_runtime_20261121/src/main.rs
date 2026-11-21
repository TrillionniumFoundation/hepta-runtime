// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Source-bound finite event/owner replay; all effectful trading paths are absent.

use anyhow::{anyhow, bail, Result};
use hepta_continuation_runtime_study::source::authenticate_source;
use hepta_continuation_runtime_study::task::{self, Completion, CompletionKind, Public, State};
use hepta_event_history_study::{basis, EventLaw, PROFILE};
use hepta_semantic_source_adapter_study::semantics::{verify_profile, ProfilePin};
use hepta_semantic_source_adapter_study::{digest, unique_json, SourcePin, MAX_JSON_BYTES};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Component, Path};

fn read(path: &Path) -> Result<Vec<u8>> {
	let file = std::fs::File::open(path)?;
	if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_JSON_BYTES as u64 {
		bail!("bounded regular input required");
	}
	let mut bytes = Vec::new();
	file.take((MAX_JSON_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	if bytes.len() > MAX_JSON_BYTES {
		bail!("input exceeded bound");
	}
	Ok(bytes)
}
fn fixture(root: &Path, path: &str) -> Result<Vec<u8>> {
	let path = Path::new(path);
	if path
		.components()
		.any(|x| !matches!(x, Component::Normal(_)))
	{
		bail!("relative fixture path required");
	}
	let path = root.join(path).canonicalize()?;
	if !path.starts_with(root) {
		bail!("fixture path escape");
	}
	read(&path)
}
fn difference(a: &[f64], b: &[f64]) -> Result<f64> {
	if a.len() != b.len() {
		bail!("oracle state shape mismatch");
	}
	let e = a
		.iter()
		.zip(b)
		.map(|(a, b)| (a - b).abs())
		.fold(0.0, f64::max);
	if e > 2e-10 {
		bail!("joint oracle mismatch: {e}");
	}
	Ok(e)
}

fn main() -> Result<()> {
	let args: Vec<_> = std::env::args().skip(1).collect();
	if args.len() != 6 {
		bail!(
			"usage: study SOURCE_MANIFEST MANIFEST_SHA LAW_SOURCE LAW_SHA ORACLE_INPUT INPUT_SHA"
		);
	}
	let manifest_path = Path::new(&args[0]).canonicalize()?;
	let root = manifest_path
		.parent()
		.ok_or_else(|| anyhow!("manifest parent"))?;
	let manifest_bytes = read(&manifest_path)?;
	let law_source = read(Path::new(&args[2]))?;
	let input_bytes = read(Path::new(&args[4]))?;
	if digest(&manifest_bytes) != args[1]
		|| digest(&law_source) != args[3]
		|| digest(&input_bytes) != args[5]
	{
		bail!("reviewed source pin mismatch");
	}
	let manifest = unique_json(&manifest_bytes)?;
	let input = unique_json(&input_bytes)?;
	if input["schema"] != "hepta.event-history-oracle.v2"
		|| input["profile"] != PROFILE
		|| input["endpoint_score_contract"]
			!= "CURRENT_JOINT_ENDPOINT_ONLY_NOT_DEADLINE_SUBMIT_OR_CONTINUATION_Q"
	{
		bail!("unknown event contract");
	}
	let pin: ProfilePin = serde_json::from_value(manifest["neuron"]["profile"]["pin"].clone())?;
	let files = manifest["neuron"]["profile"]["files"]
		.as_object()
		.ok_or_else(|| anyhow!("profile files"))?;
	let mut evidence = BTreeMap::new();
	for (role, path) in files {
		evidence.insert(
			role.clone(),
			fixture(root, path.as_str().ok_or_else(|| anyhow!("profile path"))?)?,
		);
	}
	let profile = verify_profile(&pin, &evidence)?;
	let mut results = Vec::new();
	for item in input["models"]
		.as_array()
		.ok_or_else(|| anyhow!("model inputs"))?
	{
		let original = manifest["neuron"]["models"]
			.as_array()
			.ok_or_else(|| anyhow!("source models"))?
			.iter()
			.find(|x| x["fit"] == item["fit"])
			.ok_or_else(|| anyhow!("unknown fit"))?;
		let compressed = fixture(
			root,
			original["compressed"]["path"]
				.as_str()
				.ok_or_else(|| anyhow!("checkpoint path"))?,
		)?;
		let cp: SourcePin = serde_json::from_value(original["compressed"]["pin"].clone())?;
		let jp: SourcePin = serde_json::from_value(original["decoded_pin"].clone())?;
		let source = authenticate_source(&compressed, &cp, &jp, &profile)?;
		let mut decoded = Vec::new();
		flate2::read::GzDecoder::new(compressed.as_slice()).read_to_end(&mut decoded)?;
		let law = EventLaw::authenticate(&source, &decoded, &law_source)?;
		let mut unknown_source = law_source.clone();
		unknown_source.push(b'\n');
		if EventLaw::authenticate(&source, &decoded, &unknown_source).is_ok() {
			bail!("unreviewed generator source admitted");
		}
		let public: Public = serde_json::from_value(item["public"].clone())?;
		if item["checkpoint_sha256"] != source.receipt().compressed_sha256 {
			bail!("oracle has another checkpoint");
		}
		let mut case_results = Vec::new();
		let mut overall_error: f64 = 0.0;
		let mut reconstruction_error: f64 = 0.0;
		for case in item["cases"].as_array().ok_or_else(|| anyhow!("cases"))? {
			let mut state = task::initial(&public)?;
			let mut mass = law.prior(public.prior_distance)?;
			let mut rows = Vec::new();
			let steps = case["steps"].as_array().ok_or_else(|| anyhow!("steps"))?;
			if steps.len() != 6 {
				bail!("six fixed intervals required");
			}
			for step in steps {
				let action = step["action"].as_u64().ok_or_else(|| anyhow!("action"))? as usize;
				let completion: Completion = serde_json::from_value(step["completion"].clone())?;
				let after = task::successor(&public, &state, action, completion)?;
				let expected_state: State = serde_json::from_value(step["state"].clone())?;
				if serde_json::to_vec(&after)? != serde_json::to_vec(&expected_state)? {
					bail!("existing owner state semantics differ");
				}
				let propagation =
					law.propagate(&mass, public.duration[state.tick], public.drive[state.tick])?;
				mass = propagation.mass.clone();
				let mut likelihood = None;
				if completion.kind == CompletionKind::Observation {
					likelihood = Some(
						law.observe(
							&mut mass,
							public.reliability[after.tick - 1],
							completion
								.observation
								.ok_or_else(|| anyhow!("observation"))?,
						)?,
					);
				}
				let expected: Vec<f64> = serde_json::from_value(step["joint"].clone())?;
				let error = difference(&mass, &expected)?;
				overall_error = overall_error.max(error);
				let rederived = law.belief(&public, &after)?;
				reconstruction_error = reconstruction_error.max(difference(&mass, &rederived)?);
				let serialized = serde_json::to_vec(
					&json!({"profile":PROFILE,"source":law.checkpoint_sha256,"state":after,"mass":mass}),
				)?;
				let loaded = unique_json(&serialized)?;
				let restored: Vec<f64> = serde_json::from_value(loaded["mass"].clone())?;
				if mass
					.iter()
					.zip(&restored)
					.any(|(a, b)| a.to_bits() != b.to_bits())
				{
					bail!("joint serialization bits changed");
				}
				let decoder =
					law.decode(&mass, "FIRST_OUTER_HISTORY_AND_CURRENT_ENDPOINT_SIGN_SCORE")?;
				rows.push(json!({"tick":after.tick,"endpoint_score_target_tick":after.tick,"fixed_task_target_tick":public.deadline,"consumable_as_submit_or_continuation_q":false,"action":action,"owner_state":after,"joint":mass,"decoder":decoder,"oracle_max_abs_error":error,"terms":propagation.terms,"tail_bound":propagation.omitted_tail_bound,"observation_likelihood":likelihood}));
				state = after;
			}
			case_results.push(json!({"label":case["label"],"steps":rows}));
		}
		let nodes = basis();
		let mut no_event = vec![0.0; 163];
		let mut past_reset = no_event.clone();
		no_event[nodes
			.iter()
			.position(|x| *x == (0, 15))
			.ok_or_else(|| anyhow!("known state"))?] = 1.0;
		past_reset[nodes
			.iter()
			.position(|x| *x == (3, 15))
			.ok_or_else(|| anyhow!("known state"))?] = 1.0;
		let no_decode = law.decode(
			&no_event,
			"FIRST_OUTER_HISTORY_AND_CURRENT_ENDPOINT_SIGN_SCORE",
		)?;
		let reset_decode = law.decode(
			&past_reset,
			"FIRST_OUTER_HISTORY_AND_CURRENT_ENDPOINT_SIGN_SCORE",
		)?;
		if no_decode.endpoint_at_zero != reset_decode.endpoint_at_zero
			|| no_decode.first_lower == reset_decode.first_lower
			|| reset_decode.reset_seen != 1.0
		{
			bail!("history-identifiability control failed");
		}
		let no_likelihood = law.observe(&mut no_event, public.reliability[0], 1)?;
		let reset_likelihood = law.observe(&mut past_reset, public.reliability[0], 1)?;
		let no_observed = law.decode(
			&no_event,
			"FIRST_OUTER_HISTORY_AND_CURRENT_ENDPOINT_SIGN_SCORE",
		)?;
		let reset_observed = law.decode(
			&past_reset,
			"FIRST_OUTER_HISTORY_AND_CURRENT_ENDPOINT_SIGN_SCORE",
		)?;
		if no_likelihood.to_bits() != reset_likelihood.to_bits()
			|| no_observed.endpoint_at_zero != reset_observed.endpoint_at_zero
			|| no_observed.first_lower != 0.0
			|| reset_observed.first_lower != 1.0
			|| no_observed.reset_seen != 0.0
			|| reset_observed.reset_seen != 1.0
		{
			bail!("same-observation history-identifiability control failed");
		}
		if law.propagate(&no_event, 0.0, 2).is_ok() {
			bail!("unknown drive generator admitted");
		}
		if law.decode(&no_event, "FinancialCallPut").is_ok() {
			bail!("unauthenticated financial payoff admitted");
		}
		if law.decode(&no_event, "SUBMIT_Q").is_ok()
			|| law
				.decode(&no_event, "FIRST_OUTER_HISTORY_AND_ENDPOINT_UTILITY")
				.is_ok()
		{
			bail!("current endpoint score admitted as fixed-deadline SUBMIT Q");
		}
		let mut boundary_atom = vec![0.0; 163];
		boundary_atom[nodes
			.iter()
			.position(|x| *x == (1, 31))
			.ok_or_else(|| anyhow!("boundary atom basis"))?] = 1.0;
		let atom = law.decode(
			&boundary_atom,
			"FIRST_OUTER_HISTORY_AND_CURRENT_ENDPOINT_SIGN_SCORE",
		)?;
		if atom.first_lower != 1.0 || atom.reset_seen != 0.0 {
			bail!("initial first-hit atom changed");
		}
		let mut failed = task::initial(&public)?;
		loop {
			let action = if failed.tick == 0 { 2 } else { 1 };
			let due = task::due_request(&public, &failed, action)?;
			let completion = due.map_or_else(Completion::none, Completion::failure);
			failed = task::successor(&public, &failed, action, completion)?;
			if failed.broken {
				break;
			}
		}
		let waited = task::successor(&public, &failed, 1, Completion::none())?;
		let repaired = task::successor(&public, &failed, 3, Completion::none())?;
		let wait_belief = law.belief(&public, &waited)?;
		let repair_belief = law.belief(&public, &repaired)?;
		if wait_belief
			.iter()
			.zip(&repair_belief)
			.any(|(a, b)| a.to_bits() != b.to_bits())
			|| !waited.broken
			|| repaired.broken
		{
			bail!("sensor repair changed latent event process");
		}
		source.verify_unchanged(&fixture(
			root,
			original["compressed"]["path"]
				.as_str()
				.ok_or_else(|| anyhow!("checkpoint path"))?,
		)?)?;
		results.push(json!({"fit":item["fit"],"source":source.receipt(),"cases":case_results,"whole_joint_max_abs_error":overall_error,"owner_history_reconstruction_error":reconstruction_error,"generator_reconstruction_error":law.generator_reconstruction_max_error,"known_same_endpoint_different_history":{"no_event":no_decode,"after_reset":reset_decode},"same_observation_preserves_hidden_history":{"observation":1,"reliability":public.reliability[0],"common_likelihood":no_likelihood,"no_event":no_observed,"after_reset":reset_observed},"unknown_source_rejected":true,"unknown_drive_generator_rejected":true,"initial_boundary_atom":atom,"sensor_repair_joint_latent_byte_equal":true,"financial_call_put_rejected":true,"legacy_submit_decoder_rejected":true,"original_checkpoint_bytes_unchanged":true}));
	}
	println!(
		"{}",
		serde_json::to_string(
			&json!({"schema":"hepta.native-event-history-results.v2","profile":PROFILE,"endpoint_score_contract":"CURRENT_JOINT_ENDPOINT_ONLY_NOT_DEADLINE_SUBMIT_OR_CONTINUATION_Q","status":"PASS_FINITE_EVENT_CONTRACT_V2","models":results,"new_independent_financial_labels":0,"continuous_diffusion_certified":false,"production_eligible":false})
		)?
	);
	Ok(())
}
