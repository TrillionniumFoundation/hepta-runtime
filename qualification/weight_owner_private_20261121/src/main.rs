// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Private conformance helper for a real artifact published by the canonical owner.
//! This executable neither publishes nor restores an owner transaction.

#[path = "../../weight_full_native_20261121/src/inputs.rs"]
mod inputs;

use anyhow::{anyhow, bail, Result};
use hepta_continuation_runtime_study::{source::authenticate_source, task};
use hepta_full_native_study::{codec, compare, dag, forward};
use hepta_semantic_source_adapter_study::{
	digest,
	semantics::{verify_profile, ProfilePin},
	unique_json, SourcePin, MAX_JSON_BYTES,
};
use hepta_value_intent_study::{bits, evidence::Contract, Anchor, Intent};
use inputs::{bounded, decoded_gzip, input, relative, write_new, Input};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn raw_new(path: &Path, bytes: &[u8]) -> Result<()> {
	let mut file = std::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(path)?;
	file.write_all(bytes)?;
	file.sync_all()?;
	std::fs::File::open(path.parent().ok_or_else(|| anyhow!("missing parent"))?)?.sync_all()?;
	Ok(())
}

fn file_pin(path: &Path) -> Result<Value> {
	let bytes = bounded(path)?;
	Ok(
		json!({"path":path,"pin":{"source_id":path,"size_bytes":bytes.len(),"sha256":digest(&bytes)}}),
	)
}

fn pinned(value: &Value) -> Result<Vec<u8>> {
	input(&serde_json::from_value::<Input>(value.clone())?)
}

fn verified(path: &Path, sha: &str) -> Result<Value> {
	let raw = bounded(path)?;
	SourcePin {
		source_id: path.to_string_lossy().into_owned(),
		sha256: sha.into(),
		size_bytes: raw.len() as u64,
	}
	.verify(&raw, MAX_JSON_BYTES)?;
	unique_json(&raw)
}

struct Context {
	queue: Value,
	fit: Value,
	case: Value,
	original: Value,
	compressed: Vec<u8>,
	source_path: PathBuf,
	compressed_pin: SourcePin,
	decoded_pin: SourcePin,
	profile: hepta_semantic_source_adapter_study::semantics::VerifiedProfile,
}

fn context(queue: Value) -> Result<Context> {
	if queue["schema"] != "hepta.complete-native-queue.v1"
		|| queue["arithmetic"] != forward::ARITHMETIC
	{
		bail!("C queue semantic identity differs");
	}
	let admission = unique_json(&pinned(&queue["adapter_admission"])?)?;
	if admission["schema"] != "hepta.verification-stage-native-admission.v3"
		|| admission["status"] != "ADMITTED_FOR_SEPARATE_RESEARCH_STAGE"
		|| admission["production_admission"] != false
	{
		bail!("distinct verification admission required");
	}
	let fixture = unique_json(&pinned(&queue["fixture"])?)?;
	let fixture_path = Path::new(
		queue["fixture"]["path"]
			.as_str()
			.ok_or_else(|| anyhow!("fixture path"))?,
	)
	.canonicalize()?;
	let fixture_root = fixture_path
		.parent()
		.ok_or_else(|| anyhow!("fixture root"))?;
	let neuron = &fixture["neuron"];
	let profile_pin: ProfilePin = serde_json::from_value(neuron["profile"]["pin"].clone())?;
	let files: BTreeMap<String, String> =
		serde_json::from_value(neuron["profile"]["files"].clone())?;
	let evidence = files
		.iter()
		.map(|(role, path)| Ok((role.clone(), bounded(&relative(fixture_root, path)?)?)))
		.collect::<Result<BTreeMap<_, _>>>()?;
	let profile = verify_profile(&profile_pin, &evidence)?;
	let fits = queue["fits"]
		.as_array()
		.ok_or_else(|| anyhow!("five fits required"))?;
	if fits.iter().map(|f| f["fit"].as_u64()).collect::<Vec<_>>()
		!= [Some(11), Some(23), Some(37), Some(53), Some(71)]
	{
		bail!("fixed fit order differs");
	}
	let fit = fits[0].clone();
	let cases = fit["cases"]
		.as_array()
		.ok_or_else(|| anyhow!("cases required"))?;
	if cases.len() != 8 || cases[1]["candidate_id"] != "Q_1" {
		bail!("predeclared fit11 Q_1 required");
	}
	let case = cases[1].clone();
	let models = neuron["models"]
		.as_array()
		.ok_or_else(|| anyhow!("models missing"))?;
	let matching: Vec<_> = models.iter().filter(|m| m["fit"] == 11).collect();
	if matching.len() != 1 {
		bail!("original fit11 source is not unique");
	}
	let original = matching[0].clone();
	let path = relative(
		fixture_root,
		original["compressed"]["path"]
			.as_str()
			.ok_or_else(|| anyhow!("original path"))?,
	)?;
	let compressed_pin = serde_json::from_value(original["compressed"]["pin"].clone())?;
	let decoded_pin = serde_json::from_value(original["decoded_pin"].clone())?;
	Ok(Context {
		queue,
		fit,
		case,
		original,
		compressed: bounded(&path)?,
		source_path: path,
		compressed_pin,
		decoded_pin,
		profile,
	})
}

fn prepare(queue_path: &Path, queue_sha: &str, output: &Path) -> Result<()> {
	let ctx = context(verified(queue_path, queue_sha)?)?;
	let anchor = Anchor::authenticate(
		&ctx.compressed,
		&ctx.compressed_pin,
		&ctx.decoded_pin,
		&ctx.profile,
	)?;
	let original_json = decoded_gzip(&ctx.compressed)?;
	ctx.decoded_pin.verify(&original_json, MAX_JSON_BYTES)?;
	let original_model = unique_json(&original_json)?;
	let intent: Intent = serde_json::from_value(unique_json(&pinned(&ctx.case["intent"])?)?)?;
	let contract: Contract = serde_json::from_value(unique_json(&pinned(&ctx.case["contract"])?)?)?;
	anchor.review(
		&ctx.profile,
		&intent,
		&pinned(&ctx.case["evidence"])?,
		&contract,
	)?;
	let original_bridge = codec::encode(&original_json)?;
	let expected_candidate = codec::edit(&original_bridge, &digest(&original_bridge), &intent)?;
	let candidate_model = unique_json(&codec::decode(&expected_candidate)?)?;
	if codec::weights_hash(&candidate_model)? != ctx.case["weights_sha256"]
		|| codec::protected_hash(&candidate_model)? != codec::protected_hash(&original_model)?
	{
		bail!("fixed candidate whole-model identity differs");
	}
	std::fs::create_dir(output)?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o700))?;
	}
	let original_path = output.join("original.safetensors");
	let json_path = output.join("original.json");
	let candidate_path = output.join("expected-candidate.safetensors");
	raw_new(&original_path, &original_bridge)?;
	raw_new(&json_path, &original_json)?;
	raw_new(&candidate_path, &expected_candidate)?;
	let edits = intent
		.edits
		.iter()
		.enumerate()
		.map(|(index, e)| {
			let old = bits(&e.old_bits)?.to_le_bytes();
			let new = bits(&e.new_bits)?.to_le_bytes();
			let hex = |b: &[u8]| b.iter().map(|v| format!("{v:02x}")).collect::<String>();
			Ok(json!({"index":index,"expected_hex":hex(&old),"replacement_hex":hex(&new)}))
		})
		.collect::<Result<Vec<_>>>()?;
	let manifest = json!({"schema":"hepta.private-canonical-owner-case.v1","fit":11,"candidate_id":"Q_1","queue":file_pin(queue_path)?,"helper":file_pin(&std::env::current_exe()?)?,
		"original_bridge":file_pin(&original_path)?,"original_json":file_pin(&json_path)?,"expected_candidate":file_pin(&candidate_path)?,
		"original_weights_sha256":codec::weights_hash(&original_model)?,"candidate_weights_sha256":codec::weights_hash(&candidate_model)?,"protected_fields_sha256":codec::protected_hash(&original_model)?,
		"patch":{"path":original_path,"expected_sha256":digest(&original_bridge),"tensor_name":"readout196","edits":edits},
		"arithmetic":forward::ARITHMETIC,"hardware_key":ctx.queue["hardware_key"],"full_state_reference":ctx.fit["reference"],
		"production_admission":false,"new_candidate_search":false,"source_model":ctx.original});
	write_new(&output.join("CASE.json"), &manifest)?;
	Ok(())
}

fn evaluate(
	case_path: &Path,
	case_sha: &str,
	artifact: &Path,
	output: &Path,
	restore: bool,
) -> Result<()> {
	let start = Instant::now();
	let case = verified(case_path, case_sha)?;
	if case["schema"] != "hepta.private-canonical-owner-case.v1"
		|| case["fit"] != 11
		|| case["candidate_id"] != "Q_1"
		|| case["arithmetic"] != forward::ARITHMETIC
		|| case["production_admission"] != false
	{
		bail!("private case contract differs");
	}
	if pinned(&case["helper"])? != bounded(&std::env::current_exe()?)? {
		bail!("helper binary identity differs");
	}
	let original = pinned(&case["original_bridge"])?;
	let original_json = pinned(&case["original_json"])?;
	if codec::decode(&original)? != original_json {
		bail!("original bridge JSON differs");
	}
	let actual = bounded(artifact)?;
	let actual_json = codec::decode(&actual)?;
	let model = unique_json(&actual_json)?;
	let expected = if restore {
		original.clone()
	} else {
		pinned(&case["expected_candidate"])?
	};
	let key = if restore {
		"original_weights_sha256"
	} else {
		"candidate_weights_sha256"
	};
	if actual != expected
		|| codec::weights_hash(&model)? != case[key]
		|| codec::protected_hash(&model)? != case["protected_fields_sha256"]
	{
		bail!("published owner artifact bytes/weights/protected semantics differ");
	}
	if restore {
		if actual_json != original_json {
			bail!("restore did not preserve original JSON bytes");
		}
		write_new(
			output,
			&json!({"schema":"hepta.private-owner-native-restore.v1","status":"PASS","artifact_sha256":digest(&actual),"restored_JSON_sha256":digest(&actual_json),"weights_sha256":codec::weights_hash(&model)?,"full_policy_DPs":0,"original_bytes_exact":true,"wall_seconds":start.elapsed().as_secs_f64()}),
		)?;
		return Ok(());
	}
	let ctx = context(unique_json(&pinned(&case["queue"])?)?)?;
	if ctx.queue["hardware_key"] != case["hardware_key"]
		|| ctx.fit["reference"] != case["full_state_reference"]
	{
		bail!("hardware/state reference identity differs");
	}
	let source = authenticate_source(
		&ctx.compressed,
		&ctx.compressed_pin,
		&ctx.decoded_pin,
		&ctx.profile,
	)?;
	let reference = unique_json(&pinned(&ctx.fit["reference"])?)?;
	let public: task::Public = serde_json::from_value(reference["graph"]["public"].clone())?;
	let hardware = ctx.queue["hardware_key"]
		.as_str()
		.ok_or_else(|| anyhow!("hardware key"))?;
	let graph = dag::build(&source, &model, &public, hardware)?;
	let graph_check = compare::graph(&graph, &reference)?;
	let evaluation = dag::evaluate(&graph, &codec::readout(&model)?)?;
	let policy_check = compare::policy(&evaluation, &reference["cases"]["Q_1"])?;
	source.verify_unchanged(&bounded(&ctx.source_path)?)?;
	write_new(
		output,
		&json!({"schema":"hepta.private-owner-native-evaluation.v1","status":"PASS","artifact_sha256":digest(&actual),"weights_sha256":codec::weights_hash(&model)?,"graph":graph_check,"policy":policy_check,"full_native_DAGs":1,"full_policy_DPs":1,"eligible_for_adoption":false,"scope":"existing exposed GEN semantic conformance only","wall_seconds":start.elapsed().as_secs_f64()}),
	)?;
	Ok(())
}

fn main() -> Result<()> {
	let args: Vec<_> = std::env::args().skip(1).collect();
	match args.first().map(String::as_str) {
		Some("prepare") if args.len() == 4 => {
			prepare(Path::new(&args[1]), &args[2], Path::new(&args[3]))
		}
		Some("evaluate") | Some("restored") if args.len() == 5 => evaluate(
			Path::new(&args[1]),
			&args[2],
			Path::new(&args[3]),
			Path::new(&args[4]),
			args[0] == "restored",
		),
		Some("reject-probe") if args.len() == 1 => {
			bail!("injected helper rejection; no model or DP executed")
		}
		Some("timeout-probe") if args.len() == 1 => {
			std::thread::sleep(std::time::Duration::from_secs(2));
			bail!("bounded timeout probe reached end without supervisor kill")
		}
		_ => bail!(
			"usage: prepare QUEUE SHA NEW_DIR | evaluate/restored CASE SHA ARTIFACT NEW_RECEIPT"
		),
	}
}
