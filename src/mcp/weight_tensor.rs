// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact bounded tensor-element edits derived from the admitted model directory.
//! No inference, quantization conversion or floating-point arithmetic is implicit.

use anyhow::{anyhow, bail, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExactElementEdit {
	/// Flattened element index in the declared tensor's contiguous storage.
	pub index: u64,
	/// Exact existing little-endian element bytes, lowercase hexadecimal.
	pub expected_hex: String,
	/// Exact replacement little-endian element bytes; no rounding is performed.
	pub replacement_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchTensorParams {
	/// Existing safetensors input within configured controller workspace roots.
	pub path: String,
	/// Complete source-file SHA-256, not the model header digest.
	pub expected_sha256: String,
	pub tensor_name: String,
	/// 1..=1024 distinct elements of one F32, F16 or BF16 tensor.
	pub edits: Vec<ExactElementEdit>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ByteChange {
	pub index: u64,
	pub file_offset: u64,
	pub expected_hex: String,
	pub replacement_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct TensorPatch {
	pub tensor_name: String,
	pub dtype: String,
	pub tensor_file_offset: u64,
	pub tensor_byte_length: u64,
	pub source_size_bytes: u64,
	pub changes: Vec<ByteChange>,
}

pub(super) fn unhex(text: &str) -> Result<Vec<u8>> {
	if !text.len().is_multiple_of(2) || text.len() > 8 {
		bail!("element bytes must contain at most four complete bytes");
	}
	text.as_bytes()
		.as_chunks::<2>()
		.0
		.iter()
		.map(|pair| {
			let digit = |byte| match byte {
				b'0'..=b'9' => Ok(byte - b'0'),
				b'a'..=b'f' => Ok(byte - b'a' + 10),
				_ => bail!("element bytes require lowercase hexadecimal"),
			};
			Ok(digit(pair[0])? * 16 + digit(pair[1])?)
		})
		.collect()
}

fn width(dtype: &str) -> Result<u64> {
	match dtype {
		"F32" => Ok(4),
		"F16" | "BF16" => Ok(2),
		_ => bail!("exact native weight patches support F32/F16/BF16 safetensors only"),
	}
}

fn finite(dtype: &str, bytes: &[u8]) -> Result<bool> {
	Ok(match dtype {
		"F32" => f32::from_le_bytes(bytes.try_into()?).is_finite(),
		"F16" => u16::from_le_bytes(bytes.try_into()?) & 0x7c00 != 0x7c00,
		"BF16" => u16::from_le_bytes(bytes.try_into()?) & 0x7f80 != 0x7f80,
		_ => false,
	})
}

pub(super) fn prepare(params: &PatchTensorParams, report: &Value) -> Result<TensorPatch> {
	if !super::weight_config::valid_sha256(&params.expected_sha256)
		|| params.tensor_name.is_empty()
		|| params.tensor_name.len() > 4096
		|| !(1..=1024).contains(&params.edits.len())
	{
		bail!("patch requires a full SHA-256, a bounded tensor name and 1..=1024 elements");
	}
	if report["format"] != "safetensors" {
		bail!("native tensor edits require a validated safetensors directory");
	}
	let tensor = &report["result"]["tensor"];
	if tensor["name"] != params.tensor_name || tensor["storage_length_verified"] != true {
		bail!("selected tensor identity or verified storage extent is missing");
	}
	let dtype = tensor["dtype"]
		.as_str()
		.ok_or_else(|| anyhow!("missing dtype"))?;
	let element_width = width(dtype)?;
	let file_offset = tensor["file_offset"]
		.as_u64()
		.ok_or_else(|| anyhow!("missing tensor offset"))?;
	let byte_length = tensor["byte_length"]
		.as_u64()
		.ok_or_else(|| anyhow!("unknown tensor storage length"))?;
	let size = report["source"]["size_bytes"]
		.as_u64()
		.ok_or_else(|| anyhow!("missing source size"))?;
	let header_bytes = report["source"]["header_bytes"]
		.as_u64()
		.ok_or_else(|| anyhow!("missing header extent"))?;
	if file_offset < header_bytes
		|| file_offset > size
		|| byte_length > size - file_offset
		|| byte_length % element_width != 0
	{
		bail!("tensor extent is inconsistent with the admitted safetensors file");
	}
	let elements = byte_length / element_width;
	let mut ordered = params.edits.clone();
	ordered.sort_by_key(|edit| edit.index);
	let mut changes = Vec::with_capacity(ordered.len());
	let mut previous = None;
	for edit in ordered {
		if edit.index >= elements || previous == Some(edit.index) {
			bail!("tensor edit index is out of range or repeated");
		}
		let expected = unhex(&edit.expected_hex)?;
		let replacement = unhex(&edit.replacement_hex)?;
		if expected.len() as u64 != element_width || replacement.len() as u64 != element_width {
			bail!("exact edit byte length differs from the tensor dtype");
		}
		if !finite(dtype, &expected)? || !finite(dtype, &replacement)? {
			bail!("native weight patches require finite original and replacement values");
		}
		changes.push(ByteChange {
			index: edit.index,
			file_offset: file_offset + edit.index * element_width,
			expected_hex: edit.expected_hex,
			replacement_hex: edit.replacement_hex,
		});
		previous = Some(edit.index);
	}
	Ok(TensorPatch {
		tensor_name: params.tensor_name.clone(),
		dtype: dtype.into(),
		tensor_file_offset: file_offset,
		tensor_byte_length: byte_length,
		source_size_bytes: size,
		changes,
	})
}

#[cfg(test)]
#[path = "weight_tensor_tests.rs"]
mod tests;
