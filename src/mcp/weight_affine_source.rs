// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A borrowed, source-bound F32 pair for the pure affine proposal compiler.
//! Reuses the native byte inspector and duplicate-key parser; no file is opened.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{sha, AffineParams, TensorBinding, MAX_ELEMENTS, MAX_WIDTH};

const MAX_CHECKPOINT_BYTES: usize = 32 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 256 * 1024;
const MAX_TENSORS: usize = 256;
const MAX_NAME_BYTES: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TensorDescriptor {
	dtype: String,
	shape: Vec<u64>,
	data_offsets: [u64; 2],
}

pub(super) struct Tensor<'a> {
	pub binding: TensorBinding,
	pub file_offset: usize,
	pub bytes: &'a [u8],
	pub values: Vec<f32>,
}

/// No Deserialize or public constructor: offsets originate in the checked header.
pub(super) struct Pair<'a> {
	pub weights: Tensor<'a>,
	pub bias: Tensor<'a>,
	pub header_sha256: String,
	pub tensor_map_sha256: String,
	pub inputs: usize,
	pub outputs: usize,
}

fn bounded_directory(entries: &serde_json::Map<String, Value>) -> Result<()> {
	let tensor_count = entries.len() - usize::from(entries.contains_key("__metadata__"));
	if !(2..=MAX_TENSORS).contains(&tensor_count) {
		bail!("affine source requires 2..256 tensor declarations");
	}
	for (name, value) in entries {
		if name.is_empty() || name.len() > MAX_NAME_BYTES {
			bail!("affine source tensor or metadata name exceeds its profile");
		}
		if name == "__metadata__" {
			let metadata = value
				.as_object()
				.ok_or_else(|| anyhow!("affine source metadata must be a string map"))?;
			if metadata.len() > 64
				|| metadata.iter().any(|(key, value)| {
					key.is_empty()
						|| key.len() > MAX_NAME_BYTES
						|| !value.as_str().is_some_and(|text| text.len() <= 4096)
				}) {
				bail!("affine source metadata exceeds its profile");
			}
		} else {
			let descriptor: TensorDescriptor = serde_json::from_value(value.clone())
				.context("affine source tensor declaration is invalid")?;
			if descriptor.shape.len() > 32 || descriptor.dtype.len() > 16 {
				bail!("affine source declaration exceeds its profile");
			}
		}
	}
	Ok(())
}

fn selected<'a>(
	source: &'a [u8],
	data_offset: usize,
	entries: &serde_json::Map<String, Value>,
	binding: &TensorBinding,
) -> Result<Tensor<'a>> {
	let descriptor: TensorDescriptor = serde_json::from_value(
		entries
			.get(&binding.name)
			.ok_or_else(|| anyhow!("selected affine tensor is missing"))?
			.clone(),
	)?;
	if descriptor.dtype != "F32"
		|| descriptor.dtype != binding.dtype
		|| descriptor.shape != binding.shape
	{
		bail!("selected affine tensor dtype or shape differs from its binding");
	}
	let start = data_offset
		.checked_add(usize::try_from(descriptor.data_offsets[0])?)
		.ok_or_else(|| anyhow!("affine tensor start overflow"))?;
	let end = data_offset
		.checked_add(usize::try_from(descriptor.data_offsets[1])?)
		.ok_or_else(|| anyhow!("affine tensor end overflow"))?;
	let bytes = source
		.get(start..end)
		.ok_or_else(|| anyhow!("affine tensor extends outside the source"))?;
	if bytes.is_empty()
		|| !bytes.len().is_multiple_of(4)
		|| bytes.len() / 4 > MAX_ELEMENTS
		|| sha(bytes) != binding.sha256
	{
		bail!("selected affine tensor bytes differ from their bounded identity");
	}
	let values = bytes
		.chunks_exact(4)
		.map(|chunk| {
			let value = f32::from_le_bytes(chunk.try_into()?);
			if !value.is_finite() {
				bail!("affine source coefficients must be finite");
			}
			Ok(value)
		})
		.collect::<Result<Vec<_>>>()?;
	Ok(Tensor {
		binding: binding.clone(),
		file_offset: start,
		bytes,
		values,
	})
}

pub(super) fn authenticate<'a>(params: &AffineParams, source: &'a [u8]) -> Result<Pair<'a>> {
	if !(9..=MAX_CHECKPOINT_BYTES).contains(&source.len()) {
		bail!("affine compiler admits only complete checkpoints of at most 32 MiB");
	}
	let header_length = usize::try_from(u64::from_le_bytes(source[..8].try_into()?))?;
	if !(1..=MAX_HEADER_BYTES).contains(&header_length) || source[8] != b'{' {
		bail!("affine source requires a bounded safetensors object header");
	}
	let data_offset = 8usize
		.checked_add(header_length)
		.ok_or_else(|| anyhow!("affine header extent overflow"))?;
	let header_bytes = source
		.get(8..data_offset)
		.ok_or_else(|| anyhow!("affine source header is truncated"))?;
	let header = super::super::rea_evidence::parse_unique_json(header_bytes)?;
	let entries = header
		.as_object()
		.ok_or_else(|| anyhow!("affine source header is not an object"))?;
	bounded_directory(entries)?;
	// The existing pure inspector checks the whole directory and hashes all bytes.
	// Its preview evidence identifier is not promoted to a runtime qualification.
	let report = super::super::rea::inspect_bytes(source, &params.path)?;
	let result = &report["normalized_result"];
	if result["format"] != "safetensors"
		|| result["header_facts"]["unknown_dtype_tensors"] != 0
		|| report["subject"]["sha256"].as_str() != Some(params.source_sha256.as_str())
	{
		bail!("affine source format or complete checkpoint SHA differs");
	}
	let weights = selected(source, data_offset, entries, &params.weights)?;
	let bias = selected(source, data_offset, entries, &params.bias)?;
	let outputs = usize::try_from(params.weights.shape[0])?;
	let inputs = usize::try_from(params.weights.shape[1])?;
	if !(1..=MAX_WIDTH).contains(&inputs)
		|| !(1..=MAX_WIDTH).contains(&outputs)
		|| weights.values.len() != outputs * inputs
		|| bias.values.len() != outputs
		|| weights.values.len() + bias.values.len() > MAX_ELEMENTS
	{
		bail!("affine pair exceeds the fixed dimensions or combined element cap");
	}
	let header_sha256 = sha(header_bytes);
	let tensor_map_sha256 = sha(&serde_json::to_vec(&json!({
		"source_sha256": params.source_sha256, "header_sha256": header_sha256,
		"weights": params.weights, "weight_offset": weights.file_offset,
		"bias": params.bias, "bias_offset": bias.file_offset
	}))?);
	Ok(Pair {
		weights,
		bias,
		header_sha256,
		tensor_map_sha256,
		inputs,
		outputs,
	})
}

pub(super) fn candidate_sha256(
	source: &[u8],
	replacements: &mut [(usize, [u8; 4])],
) -> Result<String> {
	replacements.sort_unstable_by_key(|(offset, _)| *offset);
	let mut hash = Sha256::new();
	let mut cursor = 0;
	for (offset, bytes) in replacements.iter() {
		let end = offset
			.checked_add(4)
			.ok_or_else(|| anyhow!("affine replacement extent overflow"))?;
		if *offset < cursor || end > source.len() {
			bail!("affine replacements overlap or extend outside the checkpoint");
		}
		hash.update(&source[cursor..*offset]);
		hash.update(bytes);
		cursor = end;
	}
	hash.update(&source[cursor..]);
	Ok(super::hex(&hash.finalize()))
}
