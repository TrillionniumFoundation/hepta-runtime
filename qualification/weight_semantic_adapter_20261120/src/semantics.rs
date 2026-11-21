// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Reviewed, source-pinned profile bindings; hashes do not prove program semantics.

use crate::descriptor::{AuthenticatedSafetensors, AuthenticatedSubset, Dtype};
use crate::{digest, unique_json, SourcePin, MAX_JSON_BYTES};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
	LayaMaskedBaFp32ActEscalateV1,
	NeuronJointRenewalEndpointF64V1,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskClass {
	ActOrEscalate,
	EndpointBinarySubmission,
	CallPut,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidencePin {
	pub role: String,
	pub source: SourcePin,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfilePin {
	pub profile: Profile,
	pub sources: Vec<EvidencePin>,
}

/// The caller must obtain pins from the reviewing owner, not a proposed edit.
/// This type authenticates bytes against those pins and does not authenticate
/// the reviewing owner, host clock, source meaning or deployed code identity.
pub struct VerifiedProfile {
	profile: Profile,
	sources: BTreeMap<String, SourcePin>,
	binding_sha256: String,
	evidence: BTreeMap<String, Vec<u8>>,
}

impl VerifiedProfile {
	pub fn binding_sha256(&self) -> &str {
		&self.binding_sha256
	}
	pub fn sources(&self) -> &BTreeMap<String, SourcePin> {
		&self.sources
	}
	fn document(&self, role: &str) -> Result<Value> {
		unique_json(
			self.evidence
				.get(role)
				.ok_or_else(|| anyhow!("missing evidence document"))?,
		)
	}
}

pub fn verify_profile(
	pin: &ProfilePin,
	evidence: &BTreeMap<String, Vec<u8>>,
) -> Result<VerifiedProfile> {
	let required: &[&str] = match pin.profile {
		Profile::NeuronJointRenewalEndpointF64V1 => &[
			"forward_code",
			"task_code",
			"arithmetic_code",
			"planning_code",
			"target_contract",
			"checkpoint_fetch_receipt",
		],
		Profile::LayaMaskedBaFp32ActEscalateV1 => &[
			"row_adapter_code",
			"action_adapter_code",
			"training_code",
			"runtime_config",
			"encoder_config",
			"base_manifest",
			"candidate_manifest",
			"origin_receipts",
			"adapter_origin_receipts",
			"head_chunk_receipts",
			"header_transfer_receipts",
		],
	};
	let optional = [
		"upstream_common_code",
		"upstream_revisions_code",
		"upstream_init_code",
	];
	if pin.sources.len() < required.len()
		|| pin.sources.len() > required.len() + optional.len()
		|| evidence.len() != pin.sources.len()
	{
		bail!("semantic evidence set is incomplete or has undeclared members");
	}
	let mut sources = BTreeMap::new();
	let mut total_bytes = 0usize;
	for item in &pin.sources {
		if !(required.contains(&item.role.as_str())
			|| pin.profile == Profile::LayaMaskedBaFp32ActEscalateV1
				&& optional.contains(&item.role.as_str()))
		{
			bail!("evidence role is not part of the selected reviewed profile");
		}
		let bytes = evidence
			.get(&item.role)
			.ok_or_else(|| anyhow!("required source evidence is missing"))?;
		item.source.verify(bytes, MAX_JSON_BYTES)?;
		total_bytes = total_bytes
			.checked_add(bytes.len())
			.ok_or_else(|| anyhow!("evidence size overflow"))?;
		if total_bytes > MAX_JSON_BYTES {
			bail!("combined semantic evidence exceeds its byte limit");
		}
		if sources
			.insert(item.role.clone(), item.source.clone())
			.is_some()
		{
			bail!("duplicate semantic evidence role");
		}
	}
	if required.iter().any(|role| !sources.contains_key(*role)) {
		bail!("required semantic source is missing");
	}
	let binding_sha256 = digest(&serde_json::to_vec(&json!({
		"profile":pin.profile,"sources":sources
	}))?);
	Ok(VerifiedProfile {
		profile: pin.profile,
		sources,
		binding_sha256,
		evidence: evidence.clone(),
	})
}

#[derive(Clone, Debug, Serialize)]
pub struct Scope {
	semantic_correctness_proven: bool,
	deployed_code_identity_verified: bool,
	remote_owner_attested: bool,
	full_graph_executed: bool,
	independent_holdout_verified: bool,
	task_value_improvement_qualified: bool,
	first_passage_repair_implemented: bool,
	sensor_repair_resets_latent: bool,
	general_ndu_optimizer: bool,
	native_cohort_edit_admitted: bool,
	weights_modified: bool,
	production_eligible: bool,
}

impl Scope {
	fn unqualified() -> Self {
		Self {
			semantic_correctness_proven: false,
			deployed_code_identity_verified: false,
			remote_owner_attested: false,
			full_graph_executed: false,
			independent_holdout_verified: false,
			task_value_improvement_qualified: false,
			first_passage_repair_implemented: false,
			sensor_repair_resets_latent: false,
			general_ndu_optimizer: false,
			native_cohort_edit_admitted: false,
			weights_modified: false,
			production_eligible: false,
		}
	}
}

#[derive(Clone, Debug, Serialize)]
pub struct SemanticReceipt {
	schema: String,
	profile: Profile,
	task_class: TaskClass,
	source_model: SourcePin,
	tensor_map_sha256: String,
	profile_sources: BTreeMap<String, SourcePin>,
	profile_sources_binding_sha256: String,
	facts: Value,
	scope: Scope,
	binding_sha256: String,
}

impl SemanticReceipt {
	pub fn binding_sha256(&self) -> &str {
		&self.binding_sha256
	}
	pub fn facts(&self) -> &Value {
		&self.facts
	}
}

fn receipt(
	profile: &VerifiedProfile,
	task: TaskClass,
	model: &SourcePin,
	map_sha: &str,
	facts: Value,
) -> Result<SemanticReceipt> {
	let mut result = SemanticReceipt {
		schema: "hepta.semantic-source-adapter.v1".into(),
		profile: profile.profile,
		task_class: task,
		source_model: model.clone(),
		tensor_map_sha256: map_sha.into(),
		profile_sources: profile.sources.clone(),
		profile_sources_binding_sha256: profile.binding_sha256.clone(),
		facts,
		scope: Scope::unqualified(),
		binding_sha256: String::new(),
	};
	// The empty self-field is an explicit versioned commitment convention.
	result.binding_sha256 = digest(&serde_json::to_vec(&result)?);
	Ok(result)
}

fn require(profile: &VerifiedProfile, expected: Profile, task: TaskClass) -> Result<()> {
	let correct_task = match expected {
		Profile::NeuronJointRenewalEndpointF64V1 => TaskClass::EndpointBinarySubmission,
		Profile::LayaMaskedBaFp32ActEscalateV1 => TaskClass::ActOrEscalate,
	};
	if profile.profile != expected || task != correct_task {
		bail!("semantic profile mismatch; ACT/ESCALATE and endpoint submission are not Call/Put");
	}
	Ok(())
}

#[derive(Clone, Debug, Serialize)]
pub struct JsonTensor {
	pub name: String,
	pub shape: Vec<usize>,
	pub dtype: Dtype,
	pub elements: usize,
	pub interpreted_f64_le_sha256: String,
	pub storage_encoding: String,
}

fn tensor_values(value: &Value, shape: &[usize], values: &mut Vec<f64>) -> Result<()> {
	if shape.is_empty() {
		let number = value
			.as_f64()
			.ok_or_else(|| anyhow!("tensor leaf is not numeric"))?;
		if !number.is_finite() {
			bail!("nonfinite F64 JSON tensor");
		}
		values.push(number);
		return Ok(());
	}
	let rows = value
		.as_array()
		.ok_or_else(|| anyhow!("tensor rank differs from profile"))?;
	if rows.len() != shape[0] {
		bail!("actual JSON tensor shape differs from profile");
	}
	for item in rows {
		tensor_values(item, &shape[1..], values)?;
	}
	Ok(())
}

fn json_tensor(name: &str, value: &Value, shape: &[usize]) -> Result<JsonTensor> {
	let mut values = Vec::new();
	tensor_values(value, shape, &mut values)?;
	let bytes: Vec<_> = values
		.iter()
		.flat_map(|value| value.to_le_bytes())
		.collect();
	Ok(JsonTensor {
		name: name.into(),
		shape: shape.to_vec(),
		dtype: Dtype::F64,
		elements: values.len(),
		interpreted_f64_le_sha256: digest(&bytes),
		storage_encoding: "JSON numeric values interpreted as IEEE754 binary64; not byte offsets"
			.into(),
	})
}

pub struct AuthenticatedNeuron {
	receipt: SemanticReceipt,
	protected_fields_sha256: String,
}

impl AuthenticatedNeuron {
	pub fn receipt(&self) -> &SemanticReceipt {
		&self.receipt
	}
	pub fn protected_fields_sha256(&self) -> &str {
		&self.protected_fields_sha256
	}
}

pub fn authenticate_neuron_json(
	bytes: &[u8],
	pin: &SourcePin,
	profile: &VerifiedProfile,
	task: TaskClass,
) -> Result<AuthenticatedNeuron> {
	require(profile, Profile::NeuronJointRenewalEndpointF64V1, task)?;
	pin.verify(bytes, MAX_JSON_BYTES)?;
	let mut model = unique_json(bytes)?;
	if model["schema"] != "joint-policy-v1"
		|| model["family"] != "renewal"
		|| model["head_dimensions"] != json!([85,48,4])
		|| model["public_dimensions"] != 43
		|| model["n_grid"] != 31
		|| model["parameter_count"] != 4332
		|| model["core"]["kind"] != "full_distribution_ctmc"
		|| model["target"] != "sign(X_deadline6)>0, including early submit; learned belief is not privileged posterior"
	{
		bail!("checkpoint does not conform to the reviewed Neuron endpoint profile");
	}
	let coordinates = model["coordinates"]
		.as_array()
		.ok_or_else(|| anyhow!("missing coordinates"))?;
	let expected: Vec<f64> = (0..31)
		.map(|i| -0.9375 + f64::from(i) / 16.0)
		.chain([-1.0, 1.0])
		.collect();
	if coordinates.len() != 33
		|| coordinates
			.iter()
			.zip(expected)
			.any(|(a, b)| a.as_f64() != Some(b))
	{
		bail!("endpoint coordinate ordering differs from the profile");
	}
	let mut auxiliary = BTreeMap::new();
	auxiliary.insert(
		"confusion".to_string(),
		json_tensor("confusion", &model["confusion"], &[2, 2])?,
	);
	auxiliary.insert(
		"core.raw".into(),
		json_tensor("core.raw", &model["core"]["raw"], &[8])?,
	);
	let tables = model["core"]["tables"]
		.as_array()
		.ok_or_else(|| anyhow!("missing transition tables"))?;
	if tables.is_empty() || tables.len() > 24 {
		bail!("transition table count outside the profile");
	}
	let mut table_keys = BTreeSet::new();
	for (index, table) in tables.iter().enumerate() {
		let dt = table["dt"]
			.as_f64()
			.filter(|v| v.is_finite() && *v > 0.0)
			.ok_or_else(|| anyhow!("invalid table time"))?;
		let drive = table["drive"]
			.as_i64()
			.filter(|v| (-1..=1).contains(v))
			.ok_or_else(|| anyhow!("invalid table drive"))?;
		if !table_keys.insert((dt.to_bits(), drive)) {
			bail!("duplicate transition table key");
		}
		let name = format!("core.tables.{index}.matrix");
		auxiliary.insert(
			name.clone(),
			json_tensor(&name, &table["matrix"], &[33, 33])?,
		);
	}
	let network = model["network"]
		.as_object()
		.ok_or_else(|| anyhow!("missing MLP network"))?;
	let shapes: [(&str, &[usize]); 4] = [
		("w1", &[48, 85]),
		("b1", &[48]),
		("w2", &[4, 48]),
		("b2", &[4]),
	];
	if network.len() != 4 || shapes.iter().any(|(key, _)| !network.contains_key(*key)) {
		bail!("MLP requires exactly the four reviewed tensor keys");
	}
	let mut tensors = BTreeMap::new();
	for (key, shape) in shapes {
		let name = format!("network.{key}");
		tensors.insert(name.clone(), json_tensor(&name, &network[key], shape)?);
	}
	model
		.as_object_mut()
		.ok_or_else(|| anyhow!("checkpoint is not an object"))?
		.remove("network");
	let protected_fields_sha256 = digest(&serde_json::to_vec(&model)?);
	let tensor_map_sha256 = digest(&serde_json::to_vec(&tensors)?);
	let facts = json!({
		"full_json_source_sha256_verified":true,
		"network_tensors":tensors,"auxiliary_tensor_descriptors":auxiliary,
		"protected_fields_sha256":protected_fields_sha256,
		"protected_hash_encoding":"serde_json sorted-object representation of all non-network fields",
		"trainable_network_coordinates":4324,"physics_metadata_coordinates":8,
		"arithmetic":"binary64; task/forward/reduction sources pinned; no execution performed",
		"representation":["public43","posterior_mass33","endpoint_bank9"],
		"scores":["STOP=0","WAIT=z0","READ=z1","REPAIR=z2","SUBMIT0=1-2*sigmoid(z3)","SUBMIT1=2*sigmoid(z3)-1"],
		"sigmoid":"1/(1+exp(-clamp(z3,-700,700)))",
		"target":"X_deadline6 > 0, including early submission",
		"sensor_repair":"sensor only; latent state is not reset by REPAIR",
		"stored_physics":"background CTMC generators may contain endogenous recovery/reset; not reexecuted",
		"native_safetensors_cohort_compatible":false,
		"implicit_F64_to_F32_conversion_performed":false
	});
	let receipt = receipt(profile, task, pin, &tensor_map_sha256, facts)?;
	Ok(AuthenticatedNeuron {
		receipt,
		protected_fields_sha256,
	})
}

pub fn validate_neuron_network_only(
	original: &AuthenticatedNeuron,
	candidate: &AuthenticatedNeuron,
) -> Result<()> {
	if original.protected_fields_sha256 != candidate.protected_fields_sha256
		|| original.receipt.profile_sources_binding_sha256
			!= candidate.receipt.profile_sources_binding_sha256
	{
		bail!("candidate changes protected physics/task fields or reviewed source semantics");
	}
	Ok(())
}

/// The raw JSON identity is derived again in Rust from the pinned original gzip.
/// Container and decoded bytes are both bound; no external decoder claim is trusted.
pub fn authenticate_neuron_gzip(
	compressed: &[u8],
	compressed_pin: &SourcePin,
	json_pin: &SourcePin,
	profile: &VerifiedProfile,
	task: TaskClass,
) -> Result<AuthenticatedNeuron> {
	compressed_pin.verify(compressed, MAX_JSON_BYTES)?;
	let origin = profile.document("checkpoint_fetch_receipt")?;
	let files = origin["files"]
		.as_array()
		.ok_or_else(|| anyhow!("repository fetch receipt has no files"))?;
	let matching: Vec<_> = files
		.iter()
		.filter(|row| {
			row["sha256"] == compressed_pin.sha256
				&& row["bytes"].as_u64() == Some(compressed_pin.size_bytes)
				&& row["url"] == compressed_pin.source_id
		})
		.collect();
	if matching.len() != 1
		|| matching[0]["git_blob_sha"]
			.as_str()
			.is_none_or(|s| s.len() != 40 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
	{
		bail!("original compressed checkpoint is not uniquely present in its pinned repository receipt");
	}
	let mut decoder = flate2::bufread::GzDecoder::new(compressed);
	let mut bytes = Vec::new();
	(&mut decoder)
		.take((MAX_JSON_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	if bytes.len() > MAX_JSON_BYTES || !decoder.into_inner().is_empty() {
		bail!("gzip source exceeds decoded bound or contains trailing/concatenated members");
	}
	let mut result = authenticate_neuron_json(&bytes, json_pin, profile, task)?;
	result.receipt.facts["original_compressed_source"] = serde_json::to_value(compressed_pin)?;
	result.receipt.facts["original_gzip_identity_and_derivation_verified"] = json!(true);
	result.receipt.facts["repository_fetch_record"] = matching[0].clone();
	result.receipt.binding_sha256.clear();
	result.receipt.binding_sha256 = digest(&serde_json::to_vec(&result.receipt)?);
	Ok(result)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LayaVariant {
	ParentPriceOnly,
	ChildPriceAndAct,
}

#[derive(Clone, Debug, Serialize)]
pub struct LayaLayer {
	pub name: String,
	pub base_shape: Vec<u64>,
	pub base_dtype: Dtype,
	pub base_payload_sha256: String,
	pub a_tensor: String,
	pub b_tensor: String,
	pub factor_dtype: Dtype,
	pub rank: u64,
	pub rows: Vec<u64>,
	pub cols: Vec<u64>,
	pub scaling: String,
	pub materialized_reference: String,
	pub runtime_forward: String,
}

fn layer(
	adapter: &AuthenticatedSafetensors<'_>,
	base: &AuthenticatedSubset,
	name: &str,
	shape: [u64; 2],
	rows: Vec<u64>,
	cols: Vec<u64>,
	rank: u64,
) -> Result<LayaLayer> {
	let a_name = format!("model.{name}.A");
	let b_name = format!("model.{name}.B");
	let a = adapter.tensor(&a_name)?;
	let b = adapter.tensor(&b_name)?;
	let base_name = format!("{name}.weight");
	let source = base
		.receipt()
		.available_tensors
		.get(&base_name)
		.ok_or_else(|| anyhow!("required complete base tensor subset is missing"))?;
	if a.dtype != Dtype::F32
		|| b.dtype != Dtype::F32
		|| a.shape != [rank, cols.len() as u64]
		|| b.shape != [rows.len() as u64, rank]
		|| source.shape != shape
		|| source.dtype != Dtype::F16
		|| rows.iter().any(|v| *v >= shape[0])
		|| cols.iter().any(|v| *v >= shape[1])
	{
		bail!("Laya rank, mask, factor orientation or F16 base shape does not match source");
	}
	Ok(LayaLayer {
		name: name.into(),
		base_shape: shape.to_vec(),
		base_dtype: Dtype::F16,
		base_payload_sha256: source
			.payload_sha256
			.clone()
			.ok_or_else(|| anyhow!("base payload lacks receipt identity"))?,
		a_tensor: a_name,
		b_tensor: b_name,
		factor_dtype: Dtype::F32,
		rank,
		rows,
		cols,
		scaling: "exactly 1; no alpha/rank multiplier".into(),
		materialized_reference: "cast F16 base to F32; masked index_add of B@A; reference only"
			.into(),
		runtime_forward:
			"base(x) plus masked F.linear(F.linear(selected_x,A),B), separately rounded".into(),
	})
}

pub fn authenticate_laya(
	adapter: &AuthenticatedSafetensors<'_>,
	base: &AuthenticatedSubset,
	manifest_bytes: &[u8],
	base_manifest_bytes: &[u8],
	profile: &VerifiedProfile,
	variant: LayaVariant,
	task: TaskClass,
) -> Result<SemanticReceipt> {
	require(profile, Profile::LayaMaskedBaFp32ActEscalateV1, task)?;
	profile
		.sources
		.get("candidate_manifest")
		.ok_or_else(|| anyhow!("missing manifest pin"))?
		.verify(manifest_bytes, MAX_JSON_BYTES)?;
	profile
		.sources
		.get("base_manifest")
		.ok_or_else(|| anyhow!("missing base manifest pin"))?
		.verify(base_manifest_bytes, MAX_JSON_BYTES)?;
	let manifest = unique_json(manifest_bytes)?;
	let base_manifest = unique_json(base_manifest_bytes)?;
	let origin = profile.document("origin_receipts")?;
	let host_record = |key: &str| -> Result<Value> {
		if origin[key]["isError"] != false {
			bail!("host identity receipt reports an error");
		}
		let text = origin[key]["content"][0]["text"]
			.as_str()
			.ok_or_else(|| anyhow!("host identity receipt is missing raw text"))?;
		unique_json(text.as_bytes())
	};
	let observed_candidate = host_record("candidate")?;
	let observed_base = host_record("base")?;
	let header_receipts = profile.document("header_transfer_receipts")?;
	let adapter_receipts = profile.document("adapter_origin_receipts")?;
	let observed_adapter = match variant {
		LayaVariant::ChildPriceAndAct => &adapter_receipts["adapter"],
		LayaVariant::ParentPriceOnly => &header_receipts["parent"],
	};
	if observed_candidate["sha256"] != digest(manifest_bytes)
		|| observed_candidate["size"].as_u64() != Some(manifest_bytes.len() as u64)
		|| observed_base["sha256"] != base.receipt().reported_full_sha256
		|| observed_base["size"].as_u64() != Some(base.receipt().header.source_size_bytes)
		|| observed_base["path"] != base.receipt().source_path
		|| observed_base["version"] != base.receipt().observed_version
		|| observed_adapter["chunk_sha256"] != adapter.receipt().source.sha256
		|| observed_adapter["path"] != adapter.receipt().source.source_id
		|| observed_adapter["size"].as_u64() != Some(adapter.receipt().source.size_bytes)
		|| observed_adapter["offset"] != 0
		|| observed_adapter["eof"] != true
		|| observed_adapter["next_offset"].as_u64() != Some(adapter.receipt().source.size_bytes)
		|| profile.sources["head_chunk_receipts"].sha256 != base.receipt().transfer_receipt_sha256
		|| profile.sources["header_transfer_receipts"].sha256
			!= base.receipt().header_transfer_receipt_sha256
	{
		bail!("actual host/hash/chunk receipts are inconsistent with the admitted sources");
	}
	let declared = &manifest["profile"];
	let revision = manifest["base_revision"]
		.as_str()
		.filter(|value| value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit()))
		.ok_or_else(|| anyhow!("actual manifest omits its exact base revision"))?;
	if manifest["schema"] != "heptatrader.laya-resident-candidate.v1"
		|| declared["dtype"] != "float32"
		|| declared["precision_policy"] != "EXPLICIT_FP32_RUNTIME_PROFILE"
		|| declared["organ_adapter"] != "FROZEN_IDENTITY"
		|| declared["action_target"] != "FROZEN_PARENT_ANSWER_CORRECTNESS_ACT_VS_ESCALATE"
		|| declared["action_target_is_trade_permission"] != false
		|| base_manifest["schema"] != "heptatrader.laya-base.v1"
		|| base_manifest["revision"].as_str() != Some(revision)
		|| base_manifest["repository"] != "convaiinnovations/laya-multilingual"
		|| base_manifest["files"]["model.safetensors"]["sha256"]
			!= base.receipt().reported_full_sha256
		|| base_manifest["files"]["model.safetensors"]["size"].as_u64()
			!= Some(base.receipt().header.source_size_bytes)
	{
		bail!("actual Laya manifest conflicts with the reviewed task, precision or base identity");
	}
	let expected_sha = match variant {
		LayaVariant::ChildPriceAndAct => manifest["adapter_sha256"].as_str(),
		LayaVariant::ParentPriceOnly => {
			manifest["action_adapter_validation"]["parent_adapter_sha256"].as_str()
		}
	}
	.ok_or_else(|| anyhow!("actual manifest omits adapter lineage digest"))?;
	if expected_sha != adapter.receipt().source.sha256 {
		bail!("adapter bytes do not match the actual manifest lineage");
	}
	let scorer1_rows: Vec<u64> = (0..4).collect();
	let scorer3_rows = vec![0_u64];
	let act_cols: Vec<u64> = (0..64).collect();
	if declared["targets"]["scorer.1"] != json!({"rows":scorer1_rows,"rank":2})
		|| declared["targets"]["scorer.3"] != json!({"rows":scorer3_rows,"rank":1})
		|| declared["action_targets"]["act_head.2"]
			!= json!({"rows":[0,1],"cols":act_cols,"rank":1})
	{
		bail!("actual adapter mask/rank is outside the reviewed narrow profile");
	}
	let mut layers = vec![
		layer(
			adapter,
			base,
			"scorer.1",
			[768, 768],
			scorer1_rows,
			(0..768).collect(),
			2,
		)?,
		layer(
			adapter,
			base,
			"scorer.3",
			[1, 768],
			scorer3_rows,
			(0..768).collect(),
			1,
		)?,
	];
	if variant == LayaVariant::ChildPriceAndAct {
		layers.push(layer(
			adapter,
			base,
			"act_head.2",
			[2, 256],
			vec![0, 1],
			act_cols,
			1,
		)?);
	} else if manifest["action_adapter_validation"]["parent_action_adapter_present"] != false {
		bail!("missing parent ACT tensors have no explicit zero-effect lineage contract");
	}
	let expected: BTreeSet<_> = layers
		.iter()
		.flat_map(|row| [row.a_tensor.clone(), row.b_tensor.clone()])
		.collect();
	if adapter
		.receipt()
		.header
		.tensors
		.keys()
		.cloned()
		.collect::<BTreeSet<_>>()
		!= expected
	{
		bail!("adapter has missing or unexplained factor tensors");
	}
	let facts = json!({
		"variant":variant,"adapter_full_source_verified":true,
		"adapter_tensor_directory":adapter.receipt().header.tensors,
		"base_evidence":base.receipt(),"layers":layers,
		"runtime_arithmetic":"explicit FP32 split adapter forward",
		"materialized_weight_arithmetic":"F16 source exactly representable in F32, masked F32 B@A plus base",
		"materialized_merge_executed":false,"split_forward_executed":false,
		"merged_and_split_bitwise_equivalence_proven":false,
		"native_factor_norm_is_effective_weight_norm":false,
		"action_labels":["ACT: frozen-parent answer correctness","ESCALATE"],
		"action_is_call_put":false,"action_is_trade_permission":false,
		"price_interface":"candidate-option scorer; price label/input/calibration contract is external",
		"full_base_checkpoint_authenticated":false,
		"subset_receipts_are_full_digest_membership_proof":false,
		"missing_parent_act_effect":"explicitly absent ACT adapter; no reconstructed A parameter identity claim"
	});
	receipt(
		profile,
		task,
		&adapter.receipt().source,
		&adapter.receipt().tensor_map_sha256,
		facts,
	)
}
