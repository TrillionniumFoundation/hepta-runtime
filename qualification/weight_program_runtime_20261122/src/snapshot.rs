// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Authenticate a lossless F64 bridge and the existing reviewed profile structure.
//!
//! Profile pins must come from the reviewing owner, outside an agent's proposed
//! edit. Matching hashes authenticate bytes against those supplied pins; they do
//! not prove the source code's meaning, owner identity, or task-value improvement.

use anyhow::{anyhow, bail, Result};
use hepta_semantic_source_adapter_study::{
	digest,
	semantics::{authenticate_neuron_json, verify_profile, ProfilePin, TaskClass},
	unique_json, SourcePin,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const WIDTH: usize = 48;
pub const ROWS: usize = 4;
pub const PARAMS: usize = 196;
pub const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EditDomain {
	ContinuationOnly,
	BeliefOnly,
	JointReadout,
}

impl EditDomain {
	pub fn permits(self, coordinate: usize) -> bool {
		if coordinate >= PARAMS {
			return false;
		}
		let row = if coordinate < ROWS * WIDTH {
			coordinate / WIDTH
		} else {
			coordinate - ROWS * WIDTH
		};
		match self {
			Self::ContinuationOnly => row < 3,
			Self::BeliefOnly => row == 3,
			Self::JointReadout => true,
		}
	}
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticSnapshot {
	pub schema: String,
	pub source_sha256: String,
	pub protected_fields_sha256: String,
	pub law_sha256: String,
	pub model_task_sha256: String,
	pub representation_sha256: String,
	pub evaluation_contract_sha256: String,
	pub profile_sources_binding_sha256: String,
	pub semantic_receipt_binding_sha256: String,
	pub tensor_name: String,
	pub layout: String,
	pub dtype: String,
	pub domain: EditDomain,
	pub head_le_hex: Vec<String>,
}

/// This token cannot be deserialized or constructed by an external caller.
/// Every compiler entry therefore requires a fresh check of real source bytes.
pub struct AuthenticatedSnapshot {
	snapshot: SemanticSnapshot,
	pub(crate) frontend: Vec<Vec<f64>>,
	pub(crate) frontend_bias: Vec<f64>,
}

/// The task payload is bound in its entirety, but its meaning remains an
/// evaluator/owner contract rather than a property proven by hashing it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationContract {
	schema: String,
	task_class: TaskClass,
	task: Value,
	profile_pin: ProfilePin,
	profile_evidence: BTreeMap<String, String>,
	profile_sources_binding_sha256: Option<String>,
}

impl AuthenticatedSnapshot {
	pub fn authenticate(
		claimed: &SemanticSnapshot,
		bridge: &[u8],
		evaluation_contract: &[u8],
	) -> Result<Self> {
		let (actual, frontend, frontend_bias) = capture_parts(
			bridge,
			&claimed.source_sha256,
			evaluation_contract,
			claimed.domain,
		)?;
		if actual.identity()? != claimed.identity()? {
			bail!("snapshot does not describe the actual source and contract");
		}
		Ok(Self {
			snapshot: actual,
			frontend,
			frontend_bias,
		})
	}

	pub fn snapshot(&self) -> &SemanticSnapshot {
		&self.snapshot
	}

	/// Compute the actual protected 85 -> 48 tanh frontend. An agent supplies an
	/// input, not a claim about the hidden activations of this checkpoint.
	pub fn hidden(&self, input: &[f64]) -> Result<Vec<f64>> {
		if input.len() != 85 || input.iter().any(|value| !value.is_finite()) {
			bail!("85 finite frontend inputs required");
		}
		self.frontend
			.iter()
			.zip(&self.frontend_bias)
			.map(|(row, bias)| {
				let preactivation = row
					.iter()
					.zip(input)
					.map(|(weight, value)| weight * value)
					.sum::<f64>() + bias;
				if !preactivation.is_finite() {
					bail!("protected frontend arithmetic overflow");
				}
				Ok(preactivation.tanh())
			})
			.collect()
	}
}

pub fn stable_l2(values: impl Iterator<Item = f64>) -> f64 {
	values.fold(0., |norm, value| norm.hypot(value))
}

pub fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn valid_digest(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn decode_f64(value: &str) -> Result<f64> {
	if value.len() != 16
		|| !value
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
	{
		bail!("exact lowercase little-endian F64 bytes required");
	}
	let mut bytes = [0_u8; 8];
	for (i, slot) in bytes.iter_mut().enumerate() {
		*slot = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)?;
	}
	let number = f64::from_le_bytes(bytes);
	if !number.is_finite() {
		bail!("nonfinite readout value");
	}
	Ok(number)
}

impl SemanticSnapshot {
	pub fn validate(&self) -> Result<Vec<f64>> {
		if self.schema != "hepta.weight-program-snapshot.v1"
			|| self.tensor_name != "readout196"
			|| self.layout != "four_row_major_48_weights_then_four_biases"
			|| self.dtype != "F64"
			|| self.head_le_hex.len() != PARAMS
		{
			bail!("reviewed readout semantics required");
		}
		for id in [
			&self.source_sha256,
			&self.protected_fields_sha256,
			&self.law_sha256,
			&self.model_task_sha256,
			&self.representation_sha256,
			&self.evaluation_contract_sha256,
			&self.profile_sources_binding_sha256,
			&self.semantic_receipt_binding_sha256,
		] {
			if !valid_digest(id) {
				bail!("complete lowercase SHA-256 identity required");
			}
		}
		self.head_le_hex.iter().map(|x| decode_f64(x)).collect()
	}

	pub fn identity(&self) -> Result<String> {
		self.validate()?;
		Ok(digest(&serde_json::to_vec(self)?))
	}

	pub fn capture(
		bridge: &[u8],
		expected_sha256: &str,
		evaluation_contract: &[u8],
		domain: EditDomain,
	) -> Result<Self> {
		Ok(capture_parts(bridge, expected_sha256, evaluation_contract, domain)?.0)
	}
}

fn capture_parts(
	bridge: &[u8],
	expected_sha256: &str,
	evaluation_contract: &[u8],
	domain: EditDomain,
) -> Result<(SemanticSnapshot, Vec<Vec<f64>>, Vec<f64>)> {
	if bridge.len() < 8 || bridge.len() > MAX_INPUT_BYTES {
		bail!("bounded complete bridge required");
	}
	if !valid_digest(expected_sha256) || digest(bridge) != expected_sha256 {
		bail!("source identity mismatch");
	}
	if evaluation_contract.is_empty() || evaluation_contract.len() > MAX_INPUT_BYTES {
		bail!("bounded evaluation contract required");
	}
	let contract: EvaluationContract = serde_json::from_value(unique_json(evaluation_contract)?)?;
	if contract.schema != "hepta.weight-program-evaluation-contract.v1"
		|| contract.task_class != TaskClass::EndpointBinarySubmission
		|| contract.task.as_object().is_none_or(|task| task.is_empty())
	{
		bail!("explicit endpoint task and evaluation contract schema required");
	}
	let profile_evidence: BTreeMap<String, Vec<u8>> = contract
		.profile_evidence
		.into_iter()
		.map(|(role, text)| (role, text.into_bytes()))
		.collect();
	let profile = verify_profile(&contract.profile_pin, &profile_evidence)?;
	if let Some(expected_binding) = &contract.profile_sources_binding_sha256 {
		if !valid_digest(expected_binding) || expected_binding != profile.binding_sha256() {
			bail!("reviewed profile source binding mismatch");
		}
	}
	let header_size = usize::try_from(u64::from_le_bytes(bridge[..8].try_into()?))?;
	let offset = header_size
		.checked_add(8)
		.ok_or_else(|| anyhow!("header length overflow"))?;
	if header_size > 262_144 || offset > bridge.len() || bridge.len() - offset < PARAMS * 8 {
		bail!("bounded readout bridge header required");
	}
	let header = unique_json(&bridge[8..offset])?;
	let original = &bridge[offset + PARAMS * 8..];
	if header.as_object().is_none_or(|m| m.len() != 3)
		|| header["readout196"] != json!({"dtype":"F64","shape":[196],"data_offsets":[0,1568]})
		|| header["original_json"]
			!= json!({"dtype":"U8","shape":[original.len()],"data_offsets":[1568,1568+original.len()]})
		|| header["__metadata__"]["hepta_bridge"] != "hepta.json-f64-readout196-bridge.v1"
		|| header["__metadata__"]["arithmetic"] != "JSON-decimal-roundtrip-to-binary64-no-cast"
		|| header["__metadata__"]
			.as_object()
			.is_none_or(|m| m.len() != 4)
		|| header["__metadata__"]["original_json_sha256"] != digest(original)
	{
		bail!("bridge layout or original identity mismatch");
	}
	let original_pin = SourcePin {
		source_id: format!("bridge:{expected_sha256}:original_json"),
		sha256: digest(original),
		size_bytes: original.len() as u64,
	};
	// Reuse the existing profile validator: target, public43, grid31,
	// parameter_count=4332, coordinates, CTMC tables, and all four tensors.
	authenticate_neuron_json(original, &original_pin, &profile, contract.task_class)?;
	let mut model = unique_json(original)?;
	if model.get("bank_semantics").is_none_or(Value::is_null) {
		bail!("bank semantics must be present and non-null");
	}
	let law_sha256 = digest(&serde_json::to_vec(&model["core"])?);
	let model_task_sha256 = digest(&serde_json::to_vec(&model["target"])?);
	let network = model["network"]
		.as_object_mut()
		.ok_or_else(|| anyhow!("network object required"))?;
	let w1: Vec<Vec<f64>> = serde_json::from_value(network["w1"].clone())?;
	let b1: Vec<f64> = serde_json::from_value(network["b1"].clone())?;
	let w2: Vec<Vec<f64>> = serde_json::from_value(network["w2"].clone())?;
	let b2: Vec<f64> = serde_json::from_value(network["b2"].clone())?;
	network.remove("w2");
	network.remove("b2");
	let protected_fields_sha256 = digest(&serde_json::to_vec(&model)?);
	if header["__metadata__"]["protected_fields_sha256"] != protected_fields_sha256 {
		bail!("protected source semantics mismatch");
	}
	let representation: Value = json!({
		"network":model["network"],"coordinates":model["coordinates"],
		"bank_semantics":model["bank_semantics"],"public_dimensions":model["public_dimensions"],
		"head_dimensions":model["head_dimensions"]
	});
	let head_le_hex: Vec<_> = bridge[offset..offset + PARAMS * 8]
		.chunks_exact(8)
		.map(hex)
		.collect();
	let head: Vec<f64> = head_le_hex
		.iter()
		.map(|value| decode_f64(value))
		.collect::<Result<_>>()?;
	// A bridge may be a previously edited immutable candidate: its current
	// binary readout can differ from the embedded original JSON. Authenticate
	// the effective model too, so the semantic receipt commits to the current
	// head rather than silently binding only the original head.
	let same_head = w2
		.iter()
		.flatten()
		.chain(&b2)
		.zip(&head)
		.all(|(old, current)| old.to_bits() == current.to_bits());
	let effective = if same_head {
		original.to_vec()
	} else {
		model["network"]["w2"] = serde_json::to_value(
			head[..ROWS * WIDTH]
				.chunks(WIDTH)
				.map(|row| row.to_vec())
				.collect::<Vec<_>>(),
		)?;
		model["network"]["b2"] = serde_json::to_value(&head[ROWS * WIDTH..])?;
		serde_json::to_vec(&model)?
	};
	let effective_model = unique_json(&effective)?;
	let effective_w2: Vec<Vec<f64>> =
		serde_json::from_value(effective_model["network"]["w2"].clone())?;
	let effective_b2: Vec<f64> = serde_json::from_value(effective_model["network"]["b2"].clone())?;
	if effective_w2
		.iter()
		.flatten()
		.chain(&effective_b2)
		.zip(&head)
		.any(|(decoded, current)| decoded.to_bits() != current.to_bits())
	{
		bail!("effective JSON roundtrip changes current F64 readout bytes");
	}
	let effective_pin = SourcePin {
		source_id: format!("bridge:{expected_sha256}:effective_neuron_json"),
		sha256: digest(&effective),
		size_bytes: effective.len() as u64,
	};
	let authenticated =
		authenticate_neuron_json(&effective, &effective_pin, &profile, contract.task_class)?;
	let snapshot = SemanticSnapshot {
		schema: "hepta.weight-program-snapshot.v1".into(),
		source_sha256: expected_sha256.into(),
		protected_fields_sha256,
		law_sha256,
		model_task_sha256,
		representation_sha256: digest(&serde_json::to_vec(&representation)?),
		evaluation_contract_sha256: digest(evaluation_contract),
		profile_sources_binding_sha256: profile.binding_sha256().into(),
		semantic_receipt_binding_sha256: authenticated.receipt().binding_sha256().into(),
		tensor_name: "readout196".into(),
		layout: "four_row_major_48_weights_then_four_biases".into(),
		dtype: "F64".into(),
		domain,
		head_le_hex,
	};
	snapshot.validate()?;
	Ok((snapshot, w1, b1))
}
