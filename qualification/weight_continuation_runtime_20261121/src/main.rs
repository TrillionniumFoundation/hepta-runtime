// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Offline real-source replay driver. All filesystem writes are new review artifacts.

use anyhow::{anyhow, bail, Context, Result};
use hepta_continuation_runtime_study::gate::{keep_unknown, ResearchByteSlot};
use hepta_continuation_runtime_study::policy::{verify_policy, Limits};
use hepta_continuation_runtime_study::session::{exercise_every_selected_step, Session};
use hepta_continuation_runtime_study::source::authenticate_source;
use hepta_continuation_runtime_study::task;
use hepta_semantic_source_adapter_study::semantics::{verify_profile, ProfilePin};
use hepta_semantic_source_adapter_study::{
	digest, unique_json, validate_sha256, SourcePin, MAX_JSON_BYTES,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileInput {
	path: String,
	pin: SourcePin,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileInput {
	pin: ProfilePin,
	files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelInput {
	fit: u64,
	compressed: FileInput,
	decoded_pin: SourcePin,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NeuronInput {
	models: Vec<ModelInput>,
	profile: ProfileInput,
}

fn bounded(path: &Path) -> Result<Vec<u8>> {
	let file = std::fs::File::open(path)
		.with_context(|| format!("open explicit input {}", path.display()))?;
	let meta = file.metadata()?;
	if !meta.is_file() || meta.len() > MAX_JSON_BYTES as u64 {
		bail!("input is not a regular bounded file");
	}
	let mut bytes = Vec::new();
	file.take((MAX_JSON_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	if bytes.len() > MAX_JSON_BYTES {
		bail!("input grew beyond byte bound");
	}
	Ok(bytes)
}

fn relative(root: &Path, path: &str) -> Result<PathBuf> {
	let path = Path::new(path);
	if path
		.components()
		.any(|part| !matches!(part, Component::Normal(_)))
	{
		bail!("fixture paths must be normal relative paths");
	}
	let path = root.join(path).canonicalize()?;
	if !path.starts_with(root) {
		bail!("fixture path escapes reviewed root");
	}
	Ok(path)
}

fn review_pin(path: &Path, bytes: &[u8], hash: &str) -> Result<SourcePin> {
	validate_sha256(hash)?;
	let pin = SourcePin {
		source_id: path.display().to_string(),
		sha256: hash.into(),
		size_bytes: bytes.len() as u64,
	};
	pin.verify(bytes, MAX_JSON_BYTES)?;
	Ok(pin)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
	let mut output = std::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(path)?;
	output.write_all(bytes)?;
	output.sync_all()?;
	Ok(())
}

fn main() -> Result<()> {
	let args: Vec<String> = std::env::args().skip(1).collect();
	if args.len() != 8 {
		bail!("usage: hepta-continuation-runtime-study FIXTURE_MANIFEST MANIFEST_SHA256 FIT CAPSULE_JSON CAPSULE_SHA256 COMPILER_SOURCE COMPILER_SHA256 NEW_REVIEW_DIRECTORY");
	}
	let started = Instant::now();
	let manifest_path = Path::new(&args[0]).canonicalize()?;
	let root = manifest_path
		.parent()
		.ok_or_else(|| anyhow!("manifest lacks parent"))?;
	let manifest_bytes = bounded(&manifest_path)?;
	review_pin(&manifest_path, &manifest_bytes, &args[1])?;
	let manifest: Value = unique_json(&manifest_bytes)?;
	if manifest["schema"] != "hepta.semantic-adapter.qualification-input.v1" {
		bail!("wrong original source manifest schema");
	}
	let neuron: NeuronInput = serde_json::from_value(manifest["neuron"].clone())?;
	let fit: u64 = args[2].parse()?;
	let models: Vec<_> = neuron.models.iter().filter(|row| row.fit == fit).collect();
	if models.len() != 1 {
		bail!("fit must uniquely identify one captured original checkpoint");
	}
	let model = models[0];
	let evidence = neuron
		.profile
		.files
		.iter()
		.map(|(role, path)| Ok((role.clone(), bounded(&relative(root, path)?)?)))
		.collect::<Result<BTreeMap<_, _>>>()?;
	let profile = verify_profile(&neuron.profile.pin, &evidence)?;
	let checkpoint_path = relative(root, &model.compressed.path)?;
	let checkpoint = bounded(&checkpoint_path)?;
	let source = authenticate_source(
		&checkpoint,
		&model.compressed.pin,
		&model.decoded_pin,
		&profile,
	)?;
	let authenticated_seconds = started.elapsed().as_secs_f64();
	let capsule_path = Path::new(&args[3]).canonicalize()?;
	let capsule = bounded(&capsule_path)?;
	let capsule_pin = review_pin(&capsule_path, &capsule, &args[4])?;
	let compiler_path = Path::new(&args[5]).canonicalize()?;
	let compiler = bounded(&compiler_path)?;
	let compiler_pin = review_pin(&compiler_path, &compiler, &args[6])?;
	let verify_start = Instant::now();
	let policy = verify_policy(
		&source,
		&capsule,
		&capsule_pin,
		&compiler,
		&compiler_pin,
		Limits::default(),
	)?;
	let verify_seconds = verify_start.elapsed().as_secs_f64();
	let compile_start = Instant::now();
	let program = policy.compile_sparse()?;
	let compile_seconds = compile_start.elapsed().as_secs_f64();
	let output = Path::new(&args[7]);
	let decision = keep_unknown(&program, "no owner-pinned future horizon, resource bounds and conversion rates for this Neuron workload");
	let mut slot = ResearchByteSlot::new(&source);
	let run = slot.run(&program, &decision, || {
		let replay_start = Instant::now();
		let exhaustive = exercise_every_selected_step(&program)?;
		let replay_seconds = replay_start.elapsed().as_secs_f64();
		std::fs::create_dir(output)
			.context("review directory must be new; existing evidence is never overwritten")?;
		let program_path = output.join("native_program.review.json");
		write_new(&program_path, program.bytes())?;
		let restored_program = policy.restore_sparse(&bounded(&program_path)?)?;
		let mut session = Session::start(&restored_program, 7)?;
		let mut trace = Vec::new();
		while !session.state().terminal {
			let action = restored_program.selected_action(session.state())?;
			let completion =
				task::completions(restored_program.public(), session.state(), action)?[0];
			trace.push(session.step(&restored_program, restored_program.public(), completion)?);
			let snapshot = session.snapshot_bytes()?;
			let path = output.join(format!("session_{}.review.json", session.steps()));
			write_new(&path, &snapshot)?;
			let loaded = bounded(&path)?;
			let pin = review_pin(&path, &loaded, &digest(&snapshot))?;
			session = Session::restore(&restored_program, &loaded, &pin)?;
		}
		Ok((exhaustive, replay_seconds, trace))
	})?;
	let restoration = run.restoration;
	let (exhaustive, replay_seconds, trace) = run
		.execution
		.map_err(|error| anyhow!("{error}; independent original byte slot restored"))?;
	if run.candidate.is_some() {
		bail!("unknown-evidence demonstration cannot save an admitted candidate");
	}
	source.verify_unchanged(slot.active_bytes())?;
	source.verify_unchanged(&bounded(&checkpoint_path)?)?;
	let receipt = json!({"schema":"hepta.native-continuation-real-replay.v1","status":"PASS_SOURCE_LAW_POLICY_EXECUTION_AND_RESTORE",
		"fit":fit,"source_manifest_sha256":args[1],"source":source.receipt(),"verification":policy.receipt(),
		"native_program":{"sha256":program.sha256(),"bytes":program.bytes().len(),"selected_states":program.state_count(),"full_capsule_bytes":capsule.len(),
			"saved_for_review_only":true,"admitted_candidate":false,"disk_restore_byte_exact":true},"exhaustive_selected_steps":exhaustive,
		"persisted_failure_first_observation_trace":trace,"restoration":restoration,"decision":decision,
		"wall_seconds":{"source_authentication":authenticated_seconds,"law_graph_verification":verify_seconds,"native_compile":compile_seconds,"all_selected_step_replay":replay_seconds,"total":started.elapsed().as_secs_f64()},
		"floating_point_contract":{"law_posteriors_and_probabilities":"absolute tolerance 2e-11; no bitwise claim", "Bellman_witnesses":"ordered original edge F64 additions, bitwise exact", "state_transitions_and_actions":"exact"},
		"scope":{"native_stored_law_propagation":true,"raw_parameter_ctmc_expm":false,"native_network_weight_edit":false,"independent_financial_labels":false,
			"external_packets_opened":false,"native_production_transaction_owner":false,"production_route_registered":false,"production_eligible":false}});
	let bytes = serde_json::to_vec_pretty(&receipt)?;
	write_new(&output.join("REPLAY_RECEIPT.json"), &bytes)?;
	println!("{}", String::from_utf8(bytes)?);
	Ok(())
}
