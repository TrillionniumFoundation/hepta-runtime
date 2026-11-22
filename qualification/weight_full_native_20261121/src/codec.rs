// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Lossless original-JSON bridge to one F64 readout tensor owned by the existing patcher.

use crate::canonical_weight_tensor::{self, ExactElementEdit, PatchTensorParams};
use anyhow::{anyhow, bail, Result};
use hepta_semantic_source_adapter_study::{digest, unique_json, MAX_JSON_BYTES};
use hepta_value_intent_study::{bits, exact, Intent};
use serde_json::{json, Value};

pub const SCHEMA: &str = "hepta.json-f64-readout196-bridge.v1";

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn readout(model: &Value) -> Result<[f64; 196]> {
	let w: Vec<Vec<f64>> = serde_json::from_value(model["network"]["w2"].clone())?;
	let b: Vec<f64> = serde_json::from_value(model["network"]["b2"].clone())?;
	if w.len() != 4 || w.iter().any(|row| row.len() != 48) || b.len() != 4 {
		bail!("F64 readout shape differs");
	}
	let all: Vec<_> = w.into_iter().flatten().chain(b).collect();
	if all.iter().any(|x| !x.is_finite()) {
		bail!("nonfinite F64 readout");
	}
	all.try_into()
		.map_err(|_| anyhow!("readout dimension differs"))
}

pub fn weights_hash(model: &Value) -> Result<String> {
	let w: Vec<Vec<f64>> = serde_json::from_value(model["network"]["w1"].clone())?;
	let b: Vec<f64> = serde_json::from_value(model["network"]["b1"].clone())?;
	if w.len() != 48 || w.iter().any(|row| row.len() != 85) || b.len() != 48 {
		bail!("hidden shape differs");
	}
	let values: Vec<_> = w
		.into_iter()
		.flatten()
		.chain(b)
		.chain(readout(model)?)
		.collect();
	if values.len() != 4324 || values.iter().any(|x| !x.is_finite()) {
		bail!("complete parameter inventory differs");
	}
	Ok(digest(
		&values
			.iter()
			.flat_map(|x| x.to_le_bytes())
			.collect::<Vec<_>>(),
	))
}

pub fn protected_hash(model: &Value) -> Result<String> {
	let mut value = model.clone();
	let network = value["network"]
		.as_object_mut()
		.ok_or_else(|| anyhow!("missing network"))?;
	network.remove("w2");
	network.remove("b2");
	Ok(digest(&serde_json::to_vec(&value)?))
}

pub fn encode(original_json: &[u8]) -> Result<Vec<u8>> {
	if original_json.len() > MAX_JSON_BYTES / 3 {
		bail!("bridge JSON size limit");
	}
	let model = unique_json(original_json)?;
	if model["schema"] != "joint-policy-v1"
		|| model["family"] != "renewal"
		|| model["head_dimensions"] != json!([85, 48, 4])
	{
		bail!("bridge requires the reviewed renewal endpoint model");
	}
	weights_hash(&model)?;
	let r = readout(&model)?;
	let mut header = serde_json::to_vec(&json!({"__metadata__":{
		"hepta_bridge":SCHEMA,"original_json_sha256":digest(original_json),
		"protected_fields_sha256":protected_hash(&model)?,"arithmetic":"JSON-decimal-roundtrip-to-binary64-no-cast"},
		"readout196":{"dtype":"F64","shape":[196],"data_offsets":[0,1568]},
		"original_json":{"dtype":"U8","shape":[original_json.len()],"data_offsets":[1568,1568+original_json.len()]}}))?;
	while !header.len().is_multiple_of(8) {
		header.push(b' ');
	}
	let mut output = (header.len() as u64).to_le_bytes().to_vec();
	output.extend(header);
	output.extend(r.iter().flat_map(|x| x.to_le_bytes()));
	output.extend_from_slice(original_json);
	Ok(output)
}

fn parse(bridge: &[u8]) -> Result<(Value, usize)> {
	if bridge.len() < 8 || bridge.len() > MAX_JSON_BYTES {
		bail!("bounded bridge required");
	}
	let size = u64::from_le_bytes(bridge[..8].try_into()?) as usize;
	if size > bridge.len() - 8 || bridge.len() - 8 - size < 1568 {
		bail!("bridge tensor length differs");
	}
	let header = unique_json(&bridge[8..8 + size])?;
	let original_size = bridge.len() - 8 - size - 1568;
	if header["__metadata__"]["hepta_bridge"] != SCHEMA
		|| header["readout196"] != json!({"dtype":"F64","shape":[196],"data_offsets":[0,1568]})
		|| header["original_json"]
			!= json!({"dtype":"U8","shape":[original_size],"data_offsets":[1568,1568+original_size]})
		|| header.as_object().is_none_or(|m| m.len() != 3)
	{
		bail!("bridge semantic format differs");
	}
	Ok((header, 8 + size))
}

pub fn decode(bridge: &[u8]) -> Result<Vec<u8>> {
	let (header, offset) = parse(bridge)?;
	let metadata = &header["__metadata__"];
	if metadata.as_object().is_none_or(|m| m.len() != 4)
		|| metadata["arithmetic"] != "JSON-decimal-roundtrip-to-binary64-no-cast"
	{
		bail!("bridge arithmetic/metadata contract differs");
	}
	let original = bridge[offset + 1568..].to_vec();
	if metadata["original_json_sha256"] != digest(&original) {
		bail!("bridge original JSON hash differs");
	}
	let mut model = unique_json(&original)?;
	if metadata["protected_fields_sha256"] != protected_hash(&model)? {
		bail!("bridge protected semantics differ");
	}
	let old = readout(&model)?;
	let values: Vec<f64> = bridge[offset..offset + 1568]
		.chunks_exact(8)
		.map(|b| Ok(f64::from_le_bytes(b.try_into()?)))
		.collect::<Result<_>>()?;
	if values.iter().any(|x| !x.is_finite()) {
		bail!("nonfinite bridge F64");
	}
	if old
		.iter()
		.zip(&values)
		.all(|(a, b)| a.to_bits() == b.to_bits())
	{
		return Ok(original);
	}
	model["network"]["w2"] = serde_json::to_value(values[..192].chunks(48).collect::<Vec<_>>())?;
	model["network"]["b2"] = serde_json::to_value(&values[192..])?;
	if metadata["protected_fields_sha256"] != protected_hash(&model)? {
		bail!("decoded edit changes protected fields");
	}
	let encoded = serde_json::to_vec(&model)?;
	if readout(&unique_json(&encoded)?)?
		.iter()
		.zip(&values)
		.any(|(a, b)| a.to_bits() != b.to_bits())
	{
		bail!("JSON F64 roundtrip changed bits");
	}
	Ok(encoded)
}

pub fn edit(original: &[u8], expected_hash: &str, intent: &Intent) -> Result<Vec<u8>> {
	if digest(original) != expected_hash
		|| intent.edits.len() != 196
		|| ![7, 8, 15].contains(&intent.row_mask)
	{
		bail!("original bridge identity or full readout intent differs");
	}
	let before = readout(&unique_json(&decode(original)?)?)?;
	let mut after = before;
	let mut edits = Vec::with_capacity(196);
	for (i, e) in intent.edits.iter().enumerate() {
		let old = bits(&e.old_bits)?;
		let new = bits(&e.new_bits)?;
		let row = if i < 192 { i / 48 } else { i - 192 };
		if old.to_bits() != before[i].to_bits()
			|| (intent.row_mask & (1 << row) == 0 && old.to_bits() != new.to_bits())
		{
			bail!("old bits or edit mask differ");
		}
		after[i] = new;
		edits.push(ExactElementEdit {
			index: i as u64,
			expected_hex: hex(&old.to_le_bytes()),
			replacement_hex: hex(&new.to_le_bytes()),
		});
	}
	let norm = exact::check(&before, &after)?;
	if !norm.within_shared_ball
		|| norm.delta_squared_units_hex != intent.delta_squared_units_hex
		|| norm.anchor_q147_squared_units_hex != intent.anchor_q147_squared_units_hex
		|| hepta_value_intent_study::readout_sha256(&after) != intent.expected_readout_sha256
	{
		bail!("fixed anchor exact shared radius or readout hash differs");
	}
	let (_, offset) = parse(original)?;
	let params = PatchTensorParams {
		path: "isolated-bridge-memory".into(),
		expected_sha256: expected_hash.into(),
		tensor_name: "readout196".into(),
		edits,
	};
	let report = json!({"format":"safetensors","source":{"size_bytes":original.len(),"header_bytes":offset},
		"result":{"tensor":{"name":"readout196","dtype":"F64","storage_length_verified":true,"file_offset":offset,"byte_length":1568}}});
	let plan = canonical_weight_tensor::prepare(&params, &report)?;
	let mut candidate = original.to_vec();
	for change in &plan.changes {
		let expected = canonical_weight_tensor::unhex(&change.expected_hex)?;
		let replacement = canonical_weight_tensor::unhex(&change.replacement_hex)?;
		let i = change.file_offset as usize;
		if candidate.get(i..i + 8) != Some(expected.as_slice()) {
			bail!("canonical owner old-byte plan differs");
		}
		candidate[i..i + 8].copy_from_slice(&replacement);
	}
	let candidate_json = decode(&candidate)?;
	if protected_hash(&unique_json(&candidate_json)?)?
		!= protected_hash(&unique_json(&decode(original)?)?)?
	{
		bail!("protected model changed");
	}
	Ok(candidate)
}
