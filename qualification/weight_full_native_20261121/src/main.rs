// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fixed five-fit, thirty-five-edit research queue; no production adoption route.

mod inputs;
use anyhow::{anyhow, bail, Result};
use hepta_continuation_runtime_study::{source::authenticate_source, task};
use hepta_full_native_study::{codec, compare, dag, forward, lifecycle};
use hepta_semantic_source_adapter_study::{
	digest,
	semantics::{verify_profile, ProfilePin},
	unique_json, SourcePin, MAX_JSON_BYTES,
};
use hepta_value_intent_study::{evidence::Contract, Anchor, Intent};
use inputs::{bounded, decoded_gzip, input, relative, write_new, Input};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
	candidate_id: String,
	model: Input,
	weights_sha256: String,
	intent: Option<Input>,
	contract: Option<Input>,
	evidence: Option<Input>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fit {
	fit: u64,
	reference: Input,
	cases: Vec<Case>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Queue {
	schema: String,
	adapter_admission: Input,
	fixture: Input,
	hardware_key: String,
	arithmetic: String,
	fits: Vec<Fit>,
}

fn main() -> Result<()> {
	let args: Vec<_> = std::env::args().skip(1).collect();
	if args.len() != 3 {
		bail!("usage: hepta-full-native-study QUEUE SHA256 NEW_OUTPUT_DIRECTORY");
	}
	let start = Instant::now();
	let raw = bounded(Path::new(&args[0]))?;
	SourcePin {
		source_id: args[0].clone(),
		sha256: args[1].clone(),
		size_bytes: raw.len() as u64,
	}
	.verify(&raw, MAX_JSON_BYTES)?;
	let queue: Queue = serde_json::from_value(unique_json(&raw)?)?;
	if queue.schema != "hepta.complete-native-queue.v1"
		|| queue.arithmetic != forward::ARITHMETIC
		|| queue.fits.iter().map(|f| f.fit).collect::<Vec<_>>() != [11, 23, 37, 53, 71]
		|| queue.hardware_key.is_empty()
	{
		bail!("frozen native queue differs");
	}
	let admission = unique_json(&input(&queue.adapter_admission)?)?;
	if admission["schema"] != "hepta.verification-stage-native-admission.v3"
		|| admission["status"] != "ADMITTED_FOR_SEPARATE_RESEARCH_STAGE"
		|| admission["production_admission"] != false
	{
		bail!("distinct verification stage admission required");
	}
	let fixture = unique_json(&input(&queue.fixture)?)?;
	let fixture_path = Path::new(&queue.fixture.path).canonicalize()?;
	let fixture_root = fixture_path
		.parent()
		.ok_or_else(|| anyhow!("fixture root missing"))?;
	let neuron = &fixture["neuron"];
	let profile_pin: ProfilePin = serde_json::from_value(neuron["profile"]["pin"].clone())?;
	let files: BTreeMap<String, String> =
		serde_json::from_value(neuron["profile"]["files"].clone())?;
	let evidence = files
		.iter()
		.map(|(role, path)| Ok((role.clone(), bounded(&relative(fixture_root, path)?)?)))
		.collect::<Result<BTreeMap<_, _>>>()?;
	let profile = verify_profile(&profile_pin, &evidence)?;
	let models = neuron["models"]
		.as_array()
		.ok_or_else(|| anyhow!("original models missing"))?;
	let output = Path::new(&args[2]);
	std::fs::create_dir(output)?;
	let mut fit_receipts = Vec::new();
	let mut passed = true;
	let mut edits = 0;
	let mut policies = 0;
	let mut injected_restorations = 0;
	for fit in queue.fits {
		let fit_start = Instant::now();
		let expected = ["KEEP", "Q_1", "B_1", "B_2", "G_1", "G_2", "T_256", "T_1024"];
		if fit
			.cases
			.iter()
			.map(|c| c.candidate_id.as_str())
			.collect::<Vec<_>>()
			!= expected
		{
			bail!("actual candidate slots differ from frozen queue");
		}
		let matching: Vec<_> = models
			.iter()
			.filter(|m| m["fit"].as_u64() == Some(fit.fit))
			.collect();
		if matching.len() != 1 {
			bail!("fit source is not unique");
		}
		let original = matching[0];
		let path = relative(
			fixture_root,
			original["compressed"]["path"]
				.as_str()
				.ok_or_else(|| anyhow!("model path missing"))?,
		)?;
		let compressed_pin: SourcePin =
			serde_json::from_value(original["compressed"]["pin"].clone())?;
		let decoded_pin: SourcePin = serde_json::from_value(original["decoded_pin"].clone())?;
		let compressed = bounded(&path)?;
		let source = authenticate_source(&compressed, &compressed_pin, &decoded_pin, &profile)?;
		let anchor = Anchor::authenticate(&compressed, &compressed_pin, &decoded_pin, &profile)?;
		let original_json = decoded_gzip(&compressed)?;
		decoded_pin.verify(&original_json, MAX_JSON_BYTES)?;
		let model = unique_json(&original_json)?;
		let original_bridge = codec::encode(&original_json)?;
		if codec::decode(&original_bridge)? != original_json {
			bail!("original JSON bytes not losslessly retained");
		}
		let bridge_hash = digest(&original_bridge);
		let reference = unique_json(&input(&fit.reference)?)?;
		let public: task::Public = serde_json::from_value(reference["graph"]["public"].clone())?;
		let graph_start = Instant::now();
		let graph = dag::build(&source, &model, &public, &queue.hardware_key)?;
		let graph_build_wall = graph_start.elapsed().as_secs_f64();
		let conformance_start = Instant::now();
		let graph_conformance = compare::graph(&graph, &reference)?;
		let graph_check_wall = conformance_start.elapsed().as_secs_f64();
		let mut active = original_bridge.clone();
		let mut rows = Vec::new();
		for (case_index, case) in fit.cases.iter().enumerate() {
			let started = Instant::now();
			let case_compressed = input(&case.model)?;
			let case_json = decoded_gzip(&case_compressed)?;
			let supplied_model = unique_json(&case_json)?;
			if codec::weights_hash(&supplied_model)? != case.weights_sha256
				|| codec::protected_hash(&supplied_model)? != codec::protected_hash(&model)?
			{
				bail!("complete weights or protected fields changed");
			}
			let candidate = if case_index == 0 {
				original_bridge.clone()
			} else {
				let intent: Intent = serde_json::from_value(unique_json(&input(
					case.intent
						.as_ref()
						.ok_or_else(|| anyhow!("intent missing"))?,
				)?)?)?;
				let contract: Contract = serde_json::from_value(unique_json(&input(
					case.contract
						.as_ref()
						.ok_or_else(|| anyhow!("contract missing"))?,
				)?)?)?;
				let supplied_evidence = input(
					case.evidence
						.as_ref()
						.ok_or_else(|| anyhow!("record missing"))?,
				)?;
				anchor.review(&profile, &intent, &supplied_evidence, &contract)?;
				edits += 1;
				codec::edit(&original_bridge, &bridge_hash, &intent)?
			};
			let prepare_wall = started.elapsed().as_secs_f64();
			let derived_model = unique_json(&codec::decode(&candidate)?)?;
			if codec::weights_hash(&derived_model)? != case.weights_sha256
				|| codec::protected_hash(&derived_model)? != codec::protected_hash(&supplied_model)?
			{
				bail!("native direct edit differs from saved full candidate weights");
			}
			dag::check_cache(
				&graph,
				&source.receipt().protected_fields_sha256,
				&public,
				&task::initial(&public)?,
				&queue.hardware_key,
			)?;
			let evaluation_start = Instant::now();
			let (outcome, restoration) =
				lifecycle::run(&mut active, &original_bridge, &candidate, |bytes| {
					let edited = unique_json(&codec::decode(bytes)?)?;
					let evaluation = dag::evaluate(&graph, &codec::readout(&edited)?)?;
					compare::policy(&evaluation, &reference["cases"][&case.candidate_id])
				})?;
			policies += 1;
			let evaluation_restore_wall = evaluation_start.elapsed().as_secs_f64();
			let result = match outcome {
				Ok(value) => value,
				Err(error) => {
					passed = false;
					json!({"error":error,"status":"FAILED"})
				}
			};
			let mut injected = None;
			if case_index == 1 {
				let (failure, restored) =
					lifecycle::run::<()>(&mut active, &original_bridge, &candidate, |_| {
						bail!("injected isolated evaluator failure")
					})?;
				if failure.is_ok() || !restored.original_bytes_exact {
					bail!("failure restoration control failed");
				}
				injected = Some(restored);
				injected_restorations += 1;
			}
			if active != original_bridge || codec::decode(&active)? != original_json {
				bail!("complete original bridge/JSON bytes not restored");
			}
			rows.push(json!({"candidate_id":case.candidate_id,"weights_sha256":case.weights_sha256,"model_pin":case.model.pin,
				"prepared_bridge_sha256":digest(&candidate),"prepare_wall_seconds":prepare_wall,
				"evaluation_validation_restore_wall_seconds":evaluation_restore_wall,"restoration":restoration,
				"injected_failure_restoration":injected,"result":result}));
		}
		source.verify_unchanged(&bounded(&path)?)?;
		anchor.verify_unchanged(&bounded(&path)?)?;
		let record = json!({"schema":"hepta.native-complete-fit.v1","fit":fit.fit,"source":source.receipt(),
			"graph":graph_conformance,"graph_build_wall_seconds":graph_build_wall,"graph_reference_check_wall_seconds":graph_check_wall,
			"rows":rows,"whole_fit_wall_seconds":fit_start.elapsed().as_secs_f64(),"original_compressed_JSON_and_all_weights_unchanged":true});
		let fit_path = output.join(format!("fit_{}.json", fit.fit));
		write_new(&fit_path, &record)?;
		fit_receipts
			.push(json!({"fit":fit.fit,"path":fit_path,"sha256":digest(&bounded(&fit_path)?)}));
	}
	if edits != 35 || policies != 40 || injected_restorations != 5 {
		bail!("fixed complete queue counters differ");
	}
	let report = json!({"schema":"hepta.native-complete-results.v1","status":if passed {"PASS"} else {"FAILED"},
		"queue_sha256":args[1],"fit_receipts":fit_receipts,"direct_parameter_edits":edits,"full_policy_DPs":policies,
		"full_native_DAGs":5,"injected_failed_callback_restorations":injected_restorations,
		"wall_seconds":start.elapsed().as_secs_f64(),"arithmetic":forward::ARITHMETIC,"hardware_key":queue.hardware_key,
		"old_native_calls_remain_zero":true,"production_owner_calls":0,"production_admission":false,
		"independent_financial_efficacy":false,"new_candidate_search":false,"new_quality_comparisons":0,
		"decision":"KEEP_ORIGINAL_AND_STOP","scope":"independent native semantic conformance of fixed exposed GEN records"});
	write_new(&output.join("NATIVE_RESULTS.json"), &report)?;
	if !passed {
		bail!("native conformance failed; every original retained");
	}
	Ok(())
}
