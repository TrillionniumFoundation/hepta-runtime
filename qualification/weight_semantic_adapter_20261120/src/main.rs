// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Offline bounded qualification driver; it reads pinned files and prints evidence.

use anyhow::{anyhow, bail, Context, Result};
use hepta_semantic_source_adapter_study::descriptor::*;
use hepta_semantic_source_adapter_study::semantics::*;
use hepta_semantic_source_adapter_study::{digest, unique_json, SourcePin, MAX_INPUT_BYTES};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

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
struct LayaInput {
	child: FileInput,
	parent: FileInput,
	prefix_path: String,
	parts: BTreeMap<String, String>,
	subset_pin: SubsetPin,
	transfer_receipt_path: String,
	header_receipt_path: String,
	profile: ProfileInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NeuronModel {
	fit: u64,
	compressed: FileInput,
	decoded_pin: SourcePin,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NeuronInput {
	models: Vec<NeuronModel>,
	profile: ProfileInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Study {
	schema: String,
	laya: LayaInput,
	neuron: NeuronInput,
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
	let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
	let metadata = file.metadata()?;
	if !metadata.is_file() || metadata.len() > limit as u64 {
		bail!("input is not a regular bounded file");
	}
	let mut bytes = Vec::new();
	file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
	if bytes.len() > limit {
		bail!("input grew beyond the bounded reader");
	}
	Ok(bytes)
}

fn read_fixture(root: &Path, relative: &str) -> Result<Vec<u8>> {
	let path = Path::new(relative);
	if path
		.components()
		.any(|part| !matches!(part, Component::Normal(_)))
	{
		bail!("fixture paths must be normal relative paths");
	}
	let path = root.join(path).canonicalize()?;
	if !path.starts_with(root) {
		bail!("fixture path resolves outside the explicit study root");
	}
	read_bounded(&path, MAX_INPUT_BYTES)
}

fn profile(
	root: &Path,
	input: &ProfileInput,
) -> Result<(VerifiedProfile, BTreeMap<String, Vec<u8>>)> {
	let evidence = input
		.files
		.iter()
		.map(|(role, path)| Ok((role.clone(), read_fixture(root, path)?)))
		.collect::<Result<BTreeMap<_, _>>>()?;
	Ok((verify_profile(&input.pin, &evidence)?, evidence))
}

fn main() -> Result<()> {
	let args: Vec<_> = std::env::args_os().skip(1).collect();
	if args.len() != 2 {
		bail!(
			"usage: hepta-semantic-source-adapter-study FIXTURE_MANIFEST EXPECTED_MANIFEST_SHA256"
		);
	}
	let path = PathBuf::from(&args[0]).canonicalize()?;
	let root = path
		.parent()
		.ok_or_else(|| anyhow!("manifest has no parent"))?;
	let bytes = read_bounded(&path, 1024 * 1024)?;
	let expected = args[1]
		.to_str()
		.ok_or_else(|| anyhow!("SHA256 argument is not UTF8"))?;
	hepta_semantic_source_adapter_study::validate_sha256(expected)?;
	if digest(&bytes) != expected {
		bail!("fixture manifest differs from the reviewer's pinned digest");
	}
	let study: Study = serde_json::from_value(unique_json(&bytes)?)?;
	if study.schema != "hepta.semantic-adapter.qualification-input.v1"
		|| study.neuron.models.len() != 5
	{
		bail!("unexpected qualification manifest schema or original-fit count");
	}
	let (laya_profile, laya_evidence) = profile(root, &study.laya.profile)?;
	let prefix = read_fixture(root, &study.laya.prefix_path)?;
	let parts = study
		.laya
		.parts
		.iter()
		.map(|(name, path)| Ok((name.clone(), read_fixture(root, path)?)))
		.collect::<Result<BTreeMap<_, _>>>()?;
	let transfer = read_fixture(root, &study.laya.transfer_receipt_path)?;
	let header_transfer = read_fixture(root, &study.laya.header_receipt_path)?;
	let subset = authenticate_subset(
		&prefix,
		&parts,
		&study.laya.subset_pin,
		&transfer,
		&header_transfer,
	)?;
	if subset.require_complete_source().is_ok() {
		bail!("subset was incorrectly promoted to a whole checkpoint");
	}
	let child_bytes = read_fixture(root, &study.laya.child.path)?;
	let parent_bytes = read_fixture(root, &study.laya.parent.path)?;
	let child = authenticate_safetensors(&child_bytes, &study.laya.child.pin)?;
	let parent = authenticate_safetensors(&parent_bytes, &study.laya.parent.pin)?;
	let manifest = laya_evidence
		.get("candidate_manifest")
		.ok_or_else(|| anyhow!("missing candidate evidence"))?;
	let base_manifest = laya_evidence
		.get("base_manifest")
		.ok_or_else(|| anyhow!("missing base evidence"))?;
	let child_semantics = authenticate_laya(
		&child,
		&subset,
		manifest,
		base_manifest,
		&laya_profile,
		LayaVariant::ChildPriceAndAct,
		TaskClass::ActOrEscalate,
	)?;
	let parent_semantics = authenticate_laya(
		&parent,
		&subset,
		manifest,
		base_manifest,
		&laya_profile,
		LayaVariant::ParentPriceOnly,
		TaskClass::ActOrEscalate,
	)?;
	let tensor = child.tensor("model.scorer.1.A")?;
	let reshaped = DescriptorClaim {
		source_file_sha256: child.receipt().source.sha256.clone(),
		tensor_name: tensor.name.clone(),
		dtype: tensor.dtype,
		shape: vec![tensor.elements],
		file_offset: tensor.file_offset,
		byte_length: tensor.byte_length,
		source_tensor_sha256: tensor
			.payload_sha256
			.clone()
			.ok_or_else(|| anyhow!("missing payload digest"))?,
	};
	if authenticate_claims(&child, &[reshaped]).is_ok() {
		bail!("real same-count implicit reshape was admitted");
	}
	if authenticate_laya(
		&child,
		&subset,
		manifest,
		base_manifest,
		&laya_profile,
		LayaVariant::ChildPriceAndAct,
		TaskClass::CallPut,
	)
	.is_ok()
	{
		bail!("actual ACT adapter was incorrectly relabeled Call/Put");
	}
	let (neuron_profile, _) = profile(root, &study.neuron.profile)?;
	let mut neurons = Vec::new();
	for input in &study.neuron.models {
		let compressed = read_fixture(root, &input.compressed.path)?;
		let verified = authenticate_neuron_gzip(
			&compressed,
			&input.compressed.pin,
			&input.decoded_pin,
			&neuron_profile,
			TaskClass::EndpointBinarySubmission,
		)?;
		neurons.push(json!({"fit":input.fit,"semantic_receipt":verified.receipt()}));
	}
	println!(
		"{}",
		serde_json::to_string_pretty(&json!({
			"schema":"hepta.semantic-adapter.real-source-qualification.v1",
			"status":"PASS_BOUNDED_SOURCE_AND_PROFILE_BINDING",
			"fixture_manifest_sha256":expected,"pocket4_parent":parent_semantics,"pocket4_child":child_semantics,
			"neuron_original_models":neurons,
			"actual_source_failures_verified":{"same_count_implicit_reshape_rejected":true,"act_to_call_put_rejected":true,"partial_base_promotion_rejected":true},
			"model_execution_count":0,"training_steps":0,"candidate_edits":0,
			"full_runtime_compiled":false,"production_route_registered":false,"production_eligible":false,
			"independent_holdout_verified":false,"default_efficacy_decision":"KEEP_ORIGINAL_AND_STOP"
		}))?
	);
	Ok(())
}
