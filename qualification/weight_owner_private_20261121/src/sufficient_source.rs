// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Versioned reader for five sealed sufficient heads, not an old Q_1 reader.

use super::*;
use hepta_semantic_source_adapter_study::semantics::{
	authenticate_neuron_json, TaskClass, VerifiedProfile,
};
use hepta_value_intent_study::{exact, readout_sha256, Edit, LAYOUT};

pub const FITS: [u64; 5] = [11, 23, 37, 53, 71];
pub const ACCEPTANCE_SHA: &str = "6f629b4b45b1ff39f4e62a321fc295d149d9c708ed26405c3b94a2317233b369";
pub const ROLE: &str = "exposed_own_law_development";

pub struct Sealed {
	pub queue: Value,
	pub entry: Value,
	pub original: Value,
	pub world: Value,
	pub source_path: PathBuf,
	pub compressed: Vec<u8>,
	pub compressed_pin: SourcePin,
	pub decoded_pin: SourcePin,
	pub profile: VerifiedProfile,
}

fn ordinary_pin(input: &Value) -> Value {
	json!({"path":input["path"],"bytes":input["pin"]["size_bytes"],"sha256":input["pin"]["sha256"]})
}

pub fn load(queue: Value, fit: u64) -> Result<Sealed> {
	if queue["schema"] != "hepta.sufficient-native-queue.v1"
		|| queue["arithmetic"] != forward::ARITHMETIC
		|| queue["role"] != ROLE
		|| queue["production_admission"] != false
		|| queue["new_candidate_search"] != false
		|| queue["value_acceptance"]["pin"]["sha256"] != ACCEPTANCE_SHA
	{
		bail!("distinct sufficient-head semantic identity required");
	}
	let admission = unique_json(&pinned(&queue["adapter_admission"])?)?;
	if admission["schema"] != "hepta.verification-stage-native-admission.v3"
		|| admission["status"] != "ADMITTED_FOR_SEPARATE_RESEARCH_STAGE"
		|| admission["production_admission"] != false
	{
		bail!("original anchor verification history is not admitted");
	}
	let acceptance = unique_json(&pinned(&queue["value_acceptance"])?)?;
	let contract = unique_json(&pinned(&queue["value_contract"])?)?;
	let results = unique_json(&pinned(&queue["value_results"])?)?;
	if acceptance["schema"] != "hepta.sufficient-compile.post-run-acceptance.v1"
		|| acceptance["status"] != "ACCEPTED_FIVE_SUFFICIENT_COMPILED_HEADS_FIXED_GRAPH_ONLY"
		|| acceptance["contract_pin"] != ordinary_pin(&queue["value_contract"])
		|| acceptance["result_pin"] != ordinary_pin(&queue["value_results"])
		|| results["status"] != "PASS"
		|| results["contract_pin"] != ordinary_pin(&queue["value_contract"])
		|| results["scope"]["production_admission"] != false
	{
		bail!("sufficient-head acceptance/contract/result cross-pins differ");
	}
	let entries = queue["fits"]
		.as_array()
		.ok_or_else(|| anyhow!("fixed fits"))?;
	if entries
		.iter()
		.map(|v| v["fit"].as_u64())
		.collect::<Vec<_>>()
		!= FITS.map(Some).to_vec()
	{
		bail!("five ordered sufficient heads required");
	}
	let index = FITS
		.iter()
		.position(|value| *value == fit)
		.ok_or_else(|| anyhow!("fit"))?;
	let entry = entries[index].clone();
	if results["outcomes"][index]["fit"] != fit
		|| results["outcomes"][index]["world_pin"] != ordinary_pin(&entry["sealed_head"])
		|| contract["queue"][index]["source_job"] != entry["source_job"]
	{
		bail!("sealed head has a different world or source job");
	}
	let world = unique_json(&decoded_gzip(&pinned(&entry["sealed_head"])?)?)?;
	if world["identity"]["source_job"] != entry["source_job"]
		|| world["decision"] != "STOP_CERTIFIED_SUFFICIENT_HEAD_AND_ACTUAL_TARGETS_PASS"
		|| world["realization"]["status"] != "EXACT_ROUNDED_RADIUS_AND_PROTECTION_PASS"
		|| world["sufficient_certificate"]["status"]
			!= "EXACT_ROUNDED_SUFFICIENT_ROWS_AND_RADIUS_PASS"
	{
		bail!("only the actual post-gate sufficient head is allowed");
	}
	let producer = contract["source_pins"]
		.as_array()
		.ok_or_else(|| anyhow!("source pins"))?
		.iter()
		.find(|p| {
			p["path"]
				.as_str()
				.is_some_and(|s| s.ends_with("/run_sufficient_compile.py"))
		})
		.ok_or_else(|| anyhow!("sufficient producer source missing"))?;
	if queue["producer_sha256"] != producer["sha256"] {
		bail!("sufficient producer identity differs");
	}
	let fixture = unique_json(&pinned(&queue["fixture"])?)?;
	let fixture_path = Path::new(
		queue["fixture"]["path"]
			.as_str()
			.ok_or_else(|| anyhow!("fixture path"))?,
	)
	.canonicalize()?;
	let root = fixture_path
		.parent()
		.ok_or_else(|| anyhow!("fixture root"))?;
	let neuron = &fixture["neuron"];
	let profile_pin: ProfilePin = serde_json::from_value(neuron["profile"]["pin"].clone())?;
	let files: BTreeMap<String, String> =
		serde_json::from_value(neuron["profile"]["files"].clone())?;
	let evidence = files
		.iter()
		.map(|(role, path)| Ok((role.clone(), bounded(&relative(root, path)?)?)))
		.collect::<Result<BTreeMap<_, _>>>()?;
	let profile = verify_profile(&profile_pin, &evidence)?;
	let originals = neuron["models"]
		.as_array()
		.ok_or_else(|| anyhow!("original models"))?;
	let matching: Vec<_> = originals.iter().filter(|m| m["fit"] == fit).collect();
	if matching.len() != 1 {
		bail!("original fit anchor is not unique");
	}
	let original = matching[0].clone();
	let compressed_pin: SourcePin = serde_json::from_value(original["compressed"]["pin"].clone())?;
	let decoded_pin = serde_json::from_value(original["decoded_pin"].clone())?;
	if entry["source_job"]["model_pin"]["sha256"] != compressed_pin.sha256
		|| entry["source_job"]["model_pin"]["bytes"] != compressed_pin.size_bytes
	{
		bail!("sealed sufficient fit is not the authenticated original anchor");
	}
	let source_path = relative(
		root,
		original["compressed"]["path"]
			.as_str()
			.ok_or_else(|| anyhow!("source path"))?,
	)?;
	let compressed = bounded(&source_path)?;
	Ok(Sealed {
		queue,
		entry,
		original,
		world,
		source_path,
		compressed,
		compressed_pin,
		decoded_pin,
		profile,
	})
}

pub fn review(source: &Sealed) -> Result<(Vec<u8>, Intent, Value)> {
	let anchor = Anchor::authenticate(
		&source.compressed,
		&source.compressed_pin,
		&source.decoded_pin,
		&source.profile,
	)?;
	let original_json = decoded_gzip(&source.compressed)?;
	source.decoded_pin.verify(&original_json, MAX_JSON_BYTES)?;
	let model = unique_json(&original_json)?;
	let before = codec::readout(&model)?;
	codec::weights_hash(&model)?;
	let original_interleaved: Vec<_> = (0..4)
		.flat_map(|row| {
			before[row * 48..row * 48 + 48]
				.iter()
				.copied()
				.chain(std::iter::once(before[192 + row]))
		})
		.flat_map(f64::to_le_bytes)
		.collect();
	let hidden_weights: Vec<Vec<f64>> = serde_json::from_value(model["network"]["w1"].clone())?;
	let hidden_bias: Vec<f64> = serde_json::from_value(model["network"]["b1"].clone())?;
	let hidden_bytes: Vec<_> = hidden_weights
		.into_iter()
		.flatten()
		.chain(hidden_bias)
		.flat_map(f64::to_le_bytes)
		.collect();
	if hidden_bytes.len() != 4128 * 8
		|| digest(&hidden_bytes) != source.world["realization"]["hidden_F64_bytes_sha256"]
		|| digest(&original_interleaved)
			!= source.world["realization"]["original_head_F64_bytes_sha256"]
	{
		bail!("source anchor/head or all 4128 protected F64 values differ");
	}
	let encoded: Vec<Vec<String>> =
		serde_json::from_value(source.world["realization"]["rounded_head_hex"].clone())?;
	if encoded.len() != 4 || encoded.iter().any(|row| row.len() != 49) {
		bail!("sealed four by forty-nine head required");
	}
	let rows: Vec<Vec<f64>> = encoded
		.iter()
		.map(|row| row.iter().map(|s| crate::sealed_hex::decode(s)).collect())
		.collect::<Result<_>>()?;
	let interleaved: Vec<_> = rows
		.iter()
		.flatten()
		.flat_map(|x| x.to_le_bytes())
		.collect();
	if digest(&interleaved) != source.world["realization"]["rounded_head_F64_bytes_sha256"] {
		bail!("sealed head F64 byte identity differs");
	}
	let after: [f64; 196] = rows
		.iter()
		.flat_map(|row| row[..48].iter().copied())
		.chain(rows.iter().map(|row| row[48]))
		.collect::<Vec<_>>()
		.try_into()
		.map_err(|_| anyhow!("readout ABI shape"))?;
	let norm = exact::check(&before, &after)?;
	if !norm.within_shared_ball {
		bail!("sealed actual head exceeds the original shared radius");
	}
	let intent = Intent {
		schema: "hepta.readout196-intent.v1".into(),
		candidate_id: format!(
			"SUFFICIENT_QB_{}",
			source.entry["fit"].as_u64().ok_or_else(|| anyhow!("fit"))?
		),
		layout: LAYOUT.into(),
		binding: anchor.binding().clone(),
		protocol_sha256: source.queue["value_contract"]["pin"]["sha256"]
			.as_str()
			.ok_or_else(|| anyhow!("contract sha"))?
			.into(),
		producer_sha256: source.queue["producer_sha256"]
			.as_str()
			.ok_or_else(|| anyhow!("producer sha"))?
			.into(),
		row_mask: 15,
		edits: before
			.iter()
			.zip(after)
			.map(|(a, b)| Edit {
				old_bits: format!("{:016x}", a.to_bits()),
				new_bits: format!("{:016x}", b.to_bits()),
			})
			.collect(),
		expected_readout_sha256: readout_sha256(&after),
		delta_squared_units_hex: norm.delta_squared_units_hex.clone(),
		anchor_q147_squared_units_hex: norm.anchor_q147_squared_units_hex.clone(),
	};
	let bridge = codec::encode(&original_json)?;
	let candidate = codec::edit(&bridge, &digest(&bridge), &intent)?;
	let decoded = codec::decode(&candidate)?;
	let preview_pin = SourcePin {
		source_id: "sufficient-head-preview".into(),
		size_bytes: decoded.len() as u64,
		sha256: digest(&decoded),
	};
	let authenticated = authenticate_neuron_json(
		&decoded,
		&preview_pin,
		&source.profile,
		TaskClass::EndpointBinarySubmission,
	)?;
	if authenticated.protected_fields_sha256() != anchor.binding().protected_law_task_sha256 {
		bail!("sufficient preview changes law or task semantics");
	}
	anchor.verify_unchanged(&bounded(&source.source_path)?)?;
	Ok((
		original_json,
		intent,
		json!({"schema":"hepta.sufficient-native-adapter-review.v1","status":"PASS",
		"role":ROLE,"exact_norm":norm,"head_interleaved_F64_sha256":digest(&interleaved),
		"hidden_F64_sha256":digest(&hidden_bytes),"original_head_interleaved_F64_sha256":digest(&original_interleaved),
		"original_semantic_anchor_authenticated":true,"new_sealed_head_identity_verified":true,
		"old_value_intent_evidence_role_reused":false,"protected_parameters":4128,
		"old_byte_plan_uses_canonical_weight_tensor":true,"NumPy_exp_certificate_transferred_to_Rust":false,
		"production_eligible":false}),
	))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn older_candidate_and_semantic_roles_are_refused_before_input_reads() {
		for schema in [
			"hepta.complete-native-queue.v1",
			"hepta.private-canonical-owner-case.v1",
			"",
		] {
			assert!(load(json!({"schema":schema}), 11).is_err());
		}
		for (field, value) in [
			("role", json!("exposed_train_generation")),
			("production_admission", json!(true)),
			("new_candidate_search", json!(true)),
			("arithmetic", json!("f32")),
		] {
			let mut queue = json!({"schema":"hepta.sufficient-native-queue.v1","arithmetic":forward::ARITHMETIC,
				"role":ROLE,"production_admission":false,"new_candidate_search":false,
				"value_acceptance":{"pin":{"sha256":ACCEPTANCE_SHA}}});
			queue[field] = value;
			assert!(load(queue, 11).is_err());
		}
	}
}
