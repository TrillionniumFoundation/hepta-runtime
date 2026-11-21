// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit pinned offline queue, at most 35 actual proposals; output is create-only.

use anyhow::{anyhow, bail, Result};
use hepta_semantic_source_adapter_study::semantics::{verify_profile, ProfilePin};
use hepta_semantic_source_adapter_study::{digest, unique_json, SourcePin, MAX_JSON_BYTES};
use hepta_value_intent_study::{evidence::Contract, Anchor, Intent};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
	path: String,
	pin: SourcePin,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
	fit: u64,
	intent: Input,
	contract: Input,
	evidence_path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Queue {
	schema: String,
	fixture_manifest: Input,
	cases: Vec<Case>,
}

fn bounded(path: &Path) -> Result<Vec<u8>> {
	let file = std::fs::File::open(path)?;
	let meta = file.metadata()?;
	if !meta.is_file() || meta.len() > MAX_JSON_BYTES as u64 {
		bail!("not a bounded regular file");
	}
	let mut bytes = Vec::new();
	file.take((MAX_JSON_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	if bytes.len() > MAX_JSON_BYTES {
		bail!("file grew beyond bound");
	}
	Ok(bytes)
}
fn input(input: &Input) -> Result<Vec<u8>> {
	let bytes = bounded(Path::new(&input.path))?;
	input.pin.verify(&bytes, MAX_JSON_BYTES)?;
	Ok(bytes)
}
fn relative(root: &Path, path: &str) -> Result<PathBuf> {
	if Path::new(path)
		.components()
		.any(|p| !matches!(p, Component::Normal(_)))
	{
		bail!("invalid fixture path");
	}
	let path = root.join(path).canonicalize()?;
	if !path.starts_with(root) {
		bail!("fixture escapes root");
	}
	Ok(path)
}
fn main() -> Result<()> {
	let args: Vec<_> = std::env::args().skip(1).collect();
	if args.len() != 3 {
		bail!("usage: hepta-value-intent-study QUEUE_JSON QUEUE_SHA256 NEW_REPORT");
	}
	let raw = bounded(Path::new(&args[0]))?;
	SourcePin {
		source_id: args[0].clone(),
		sha256: args[1].clone(),
		size_bytes: raw.len() as u64,
	}
	.verify(&raw, MAX_JSON_BYTES)?;
	let queue: Queue = serde_json::from_value(unique_json(&raw)?)?;
	if queue.schema != "hepta.intent-qualification-queue.v1"
		|| queue.cases.is_empty()
		|| queue.cases.len() > 35
	{
		bail!("invalid bounded queue");
	}
	let fixture = unique_json(&input(&queue.fixture_manifest)?)?;
	if fixture["schema"] != "hepta.semantic-adapter.qualification-input.v1" {
		bail!("wrong fixture schema");
	}
	let path = Path::new(&queue.fixture_manifest.path).canonicalize()?;
	let root = path
		.parent()
		.ok_or_else(|| anyhow!("fixture has no parent"))?;
	let neuron = &fixture["neuron"];
	let profile_pin: ProfilePin = serde_json::from_value(neuron["profile"]["pin"].clone())?;
	let files: BTreeMap<String, String> =
		serde_json::from_value(neuron["profile"]["files"].clone())?;
	let sources = files
		.iter()
		.map(|(role, path)| Ok((role.clone(), bounded(&relative(root, path)?)?)))
		.collect::<Result<BTreeMap<_, _>>>()?;
	let profile = verify_profile(&profile_pin, &sources)?;
	let models = neuron["models"]
		.as_array()
		.ok_or_else(|| anyhow!("missing model list"))?;
	let mut seen = BTreeSet::new();
	let mut rows = Vec::new();
	let mut passed = true;
	for case in queue.cases {
		let matching: Vec<_> = models
			.iter()
			.filter(|m| m["fit"].as_u64() == Some(case.fit))
			.collect();
		if matching.len() != 1 {
			bail!("fit is not uniquely bound");
		}
		let model = matching[0];
		let source_path = relative(
			root,
			model["compressed"]["path"]
				.as_str()
				.ok_or_else(|| anyhow!("source path"))?,
		)?;
		let compressed_pin: SourcePin = serde_json::from_value(model["compressed"]["pin"].clone())?;
		let decoded_pin: SourcePin = serde_json::from_value(model["decoded_pin"].clone())?;
		let before = bounded(&source_path)?;
		let started = Instant::now();
		let anchor = Anchor::authenticate(&before, &compressed_pin, &decoded_pin, &profile)?;
		let auth_wall_seconds = started.elapsed().as_secs_f64();
		let intent: Intent = serde_json::from_value(unique_json(&input(&case.intent)?)?)?;
		if !seen.insert((case.fit, intent.candidate_id.clone())) {
			bail!("duplicate intent in queue");
		}
		let contract: Contract = serde_json::from_value(unique_json(&input(&case.contract)?)?)?;
		let evidence = bounded(Path::new(&case.evidence_path))?;
		let started = Instant::now();
		let review = anchor.review(&profile, &intent, &evidence, &contract);
		let preview_admission_wall_seconds = started.elapsed().as_secs_f64();
		let started = Instant::now();
		anchor.verify_unchanged(&bounded(&source_path)?)?;
		let unchanged_rehash_wall_seconds = started.elapsed().as_secs_f64();
		let result: Value = match review {
			Ok(review) => serde_json::to_value(review)?,
			Err(error) => {
				passed = false;
				json!({"decision":"KEEP_ORIGINAL_AND_STOP","rejected":error.to_string(),"production_owner_called":false})
			}
		};
		rows.push(json!({"fit":case.fit,"candidate_id":intent.candidate_id,"binding":anchor.binding(),
			"intent_sha256":case.intent.pin.sha256,"contract_sha256":case.contract.pin.sha256,
			"evidence_sha256":digest(&evidence),"original_bytes_unchanged":true,
			"auth_wall_seconds":auth_wall_seconds,"preview_admission_wall_seconds":preview_admission_wall_seconds,
			"unchanged_rehash_wall_seconds":unchanged_rehash_wall_seconds,"result":result}));
	}
	let report = json!({"schema":"hepta.intent-qualification-result.v1","queue_sha256":args[1],
		"passed":passed,"actual_intents":rows.len(),"rows":rows,
		"scope":"offline typed admission; no forward, DAG, training or production owner invocation",
		"restoration":"immutable original plus discarded private preview; no production transaction rollback exercised"});
	let mut output = std::fs::OpenOptions::new()
		.write(true)
		.create_new(true)
		.open(&args[2])?;
	output.write_all(&serde_json::to_vec_pretty(&report)?)?;
	output.write_all(b"\n")?;
	output.sync_all()?;
	if !passed {
		bail!("one or more intents rejected; original retained");
	}
	Ok(())
}
