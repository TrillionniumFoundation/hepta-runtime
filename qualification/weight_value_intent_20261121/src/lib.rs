// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Typed offline F64 proposals. No production writer, registration or owner call.

pub mod evidence;
pub mod exact;
use anyhow::{anyhow, bail, Result};
use hepta_continuation_runtime_study::source::{authenticate_source, VerifiedSource};
use hepta_semantic_source_adapter_study::semantics::{
	authenticate_neuron_json, TaskClass, VerifiedProfile,
};
use hepta_semantic_source_adapter_study::{digest, unique_json, SourcePin, MAX_JSON_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Read;

pub const LAYOUT: &str = "network.w2.row_major_192_then_network.b2_4.f64bits.v1";
pub const MAIN_OWNER: &str = "d3d75c30719db966b004756f610007a7c723729e";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
	pub compressed_sha256: String,
	pub decoded_sha256: String,
	pub profile_sha256: String,
	pub protected_law_task_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edit {
	pub old_bits: String,
	pub new_bits: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
	pub schema: String,
	pub candidate_id: String,
	pub layout: String,
	pub binding: Binding,
	pub protocol_sha256: String,
	pub producer_sha256: String,
	pub row_mask: u8,
	pub edits: Vec<Edit>,
	pub expected_readout_sha256: String,
	pub delta_squared_units_hex: String,
	pub anchor_q147_squared_units_hex: String,
}

pub struct Anchor {
	source: VerifiedSource,
	model: Value,
	binding: Binding,
	readout: [f64; 196],
}

fn readout(model: &Value) -> Result<[f64; 196]> {
	let w: Vec<Vec<f64>> = serde_json::from_value(model["network"]["w2"].clone())?;
	let b: [f64; 4] = serde_json::from_value(model["network"]["b2"].clone())?;
	if w.len() != 4 || w.iter().any(|row| row.len() != 48) {
		bail!("readout shape differs");
	}
	let values: Vec<_> = w.into_iter().flatten().chain(b).collect();
	values
		.try_into()
		.map_err(|_| anyhow!("readout dimension differs"))
}

pub fn readout_sha256(values: &[f64; 196]) -> String {
	digest(
		&values
			.iter()
			.flat_map(|x| x.to_le_bytes())
			.collect::<Vec<_>>(),
	)
}

pub fn bits(value: &str) -> Result<f64> {
	if value.len() != 16
		|| !value
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
	{
		bail!("F64 bits require 16 lowercase hexadecimal characters");
	}
	let parsed = f64::from_bits(u64::from_str_radix(value, 16)?);
	if !parsed.is_finite() {
		bail!("nonfinite parameter bits");
	}
	Ok(parsed)
}

fn prepare_readout(
	before: &[f64; 196],
	intent: &Intent,
	contract: &evidence::Contract,
) -> Result<([f64; 196], exact::NormReceipt)> {
	if intent.schema != "hepta.readout196-intent.v1"
		|| intent.layout != LAYOUT
		|| intent.edits.len() != 196
		|| ![7, 8, 15].contains(&intent.row_mask)
	{
		bail!("intent schema, layout, row mask or dimension mismatch");
	}
	contract.check_intent(intent)?;
	let mut candidate = *before;
	for (i, edit) in intent.edits.iter().enumerate() {
		let old = bits(&edit.old_bits)?;
		let new = bits(&edit.new_bits)?;
		let row = if i < 192 { i / 48 } else { i - 192 };
		if old.to_bits() != before[i].to_bits()
			|| (intent.row_mask & (1 << row) == 0 && old.to_bits() != new.to_bits())
		{
			bail!("old bits differ or edit touches an excluded row");
		}
		candidate[i] = new;
	}
	let norm = exact::check(before, &candidate)?;
	if !norm.within_shared_ball
		|| norm.delta_squared_units_hex != intent.delta_squared_units_hex
		|| norm.anchor_q147_squared_units_hex != intent.anchor_q147_squared_units_hex
		|| readout_sha256(&candidate) != intent.expected_readout_sha256
	{
		bail!("exact shared radius, integer witness or readout digest differs");
	}
	Ok((candidate, norm))
}

fn owner_reason(revision: &str) -> &'static str {
	if revision == MAIN_OWNER {
		"UNSUPPORTED_JSON_F64"
	} else {
		"UNREVIEWED_OWNER_REVISION"
	}
}

impl Anchor {
	pub fn authenticate(
		bytes: &[u8],
		gzip: &SourcePin,
		json: &SourcePin,
		profile: &VerifiedProfile,
	) -> Result<Self> {
		let source = authenticate_source(bytes, gzip, json, profile)?;
		let mut decoded = Vec::new();
		flate2::read::GzDecoder::new(bytes)
			.take((MAX_JSON_BYTES + 1) as u64)
			.read_to_end(&mut decoded)?;
		json.verify(&decoded, MAX_JSON_BYTES)?;
		let model = unique_json(&decoded)?;
		let receipt = source.receipt();
		let binding = Binding {
			compressed_sha256: receipt.compressed_sha256.clone(),
			decoded_sha256: receipt.decoded_sha256.clone(),
			profile_sha256: receipt.profile_binding_sha256.clone(),
			protected_law_task_sha256: receipt.protected_fields_sha256.clone(),
		};
		Ok(Self {
			source,
			readout: readout(&model)?,
			model,
			binding,
		})
	}
	pub fn binding(&self) -> &Binding {
		&self.binding
	}
	pub fn verify_unchanged(&self, bytes: &[u8]) -> Result<()> {
		self.source.verify_unchanged(bytes)
	}
	pub fn review(
		&self,
		profile: &VerifiedProfile,
		intent: &Intent,
		evidence_bytes: &[u8],
		contract: &evidence::Contract,
	) -> Result<Review> {
		if intent.binding != self.binding || profile.binding_sha256() != self.binding.profile_sha256
		{
			bail!("intent source or semantic profile differs from the authenticated anchor");
		}
		let (candidate, norm) = prepare_readout(&self.readout, intent, contract)?;
		// Only this owned clone is edited. The authenticated original has no mutable API.
		let mut preview = self.model.clone();
		preview["network"]["w2"] =
			serde_json::to_value(candidate[..192].chunks(48).collect::<Vec<_>>())?;
		preview["network"]["b2"] = serde_json::to_value(&candidate[192..])?;
		let bytes = serde_json::to_vec(&preview)?;
		let pin = SourcePin {
			source_id: "derived-memory-preview".into(),
			sha256: digest(&bytes),
			size_bytes: bytes.len() as u64,
		};
		let verified =
			authenticate_neuron_json(&bytes, &pin, profile, TaskClass::EndpointBinarySubmission)?;
		if verified.protected_fields_sha256() != self.binding.protected_law_task_sha256
			|| readout(&preview)?
				.iter()
				.zip(candidate)
				.any(|(a, b)| a.to_bits() != b.to_bits())
		{
			bail!("preview changes protected semantics or represented bits");
		}
		contract
			.evidence_pin
			.verify(evidence_bytes, MAX_JSON_BYTES)?;
		let evidence: evidence::Evidence = serde_json::from_value(unique_json(evidence_bytes)?)?;
		contract.check_evidence(intent, &evidence)?;
		Ok(Review {
			candidate_id: intent.candidate_id.clone(),
			norm,
			preview_sha256: pin.sha256,
			readout_sha256: intent.expected_readout_sha256.clone(),
			evaluator_role: evidence.role,
			supplied_own_law_gain: evidence.candidate_value - evidence.original_value,
			decision: "KEEP_ORIGINAL_AND_STOP",
			owner_reason: owner_reason(&contract.owner_revision),
			production_eligible: false,
			production_owner_called: false,
			native_dag_recomputed: false,
			independent_financial_labels_verified: false,
			sealed_sample_independence_verified: false,
			review_contract_signature_verified: false,
			owner_attestation_verified: false,
		})
	}
}

#[derive(Serialize)]
pub struct Review {
	pub candidate_id: String,
	pub norm: exact::NormReceipt,
	pub preview_sha256: String,
	pub readout_sha256: String,
	pub evaluator_role: evidence::Role,
	pub supplied_own_law_gain: f64,
	pub decision: &'static str,
	pub owner_reason: &'static str,
	pub production_eligible: bool,
	pub production_owner_called: bool,
	pub native_dag_recomputed: bool,
	pub independent_financial_labels_verified: bool,
	pub sealed_sample_independence_verified: bool,
	pub review_contract_signature_verified: bool,
	pub owner_attestation_verified: bool,
}

#[cfg(test)]
#[path = "intent_tests.rs"]
mod tests;
