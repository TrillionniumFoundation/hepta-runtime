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

//! Capture both head tensors inside the second complete-source hash pass.
//! No path is opened, coefficient encoded, artifact created or owner invoked.

use anyhow::{anyhow, bail, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::super::super::{rea_model, weight_f16_proposal::TensorBinding, weight_tensor};
use super::{check_deadline, sha, CoupledF16EvaluationParams, Shape};

const MAX_MODEL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_HEADER_BYTES: u64 = 256 * 1024;
const STREAM_BYTES: usize = 1024 * 1024;

pub(super) struct CapturedHead {
	pub source_size_bytes: u64,
	pub observed_version: String,
	pub raw_prefix_sha256: String,
	pub json_header_sha256: String,
	pub weight_bytes: Vec<u8>,
	pub bias_bytes: Vec<u8>,
	pub weight_offset: u64,
	pub bias_offset: u64,
}

struct Extent {
	start: u64,
	length: usize,
}

fn extent(
	report: &Value,
	binding: &TensorBinding,
	length: usize,
	prefix: u64,
	size: u64,
) -> Result<Extent> {
	let tensor = report["result"]["tensors"]
		.as_array()
		.and_then(|tensors| {
			tensors
				.iter()
				.find(|tensor| tensor["name"].as_str() == Some(binding.name.as_str()))
		})
		.ok_or_else(|| anyhow!("coupled F16 tensor is missing from the admitted directory"))?;
	let shape: Vec<_> = binding.shape.iter().map(u64::to_string).collect();
	if tensor["dtype"] != "F16"
		|| tensor["shape"] != serde_json::to_value(shape)?
		|| tensor["storage_length_verified"] != true
		|| tensor["byte_length"].as_u64() != Some(length as u64)
	{
		bail!("coupled F16 tensor dtype, shape or length differs from its binding");
	}
	let start = tensor["file_offset"]
		.as_u64()
		.ok_or_else(|| anyhow!("coupled F16 tensor offset is missing"))?;
	if start < prefix || start > size || length as u64 > size - start {
		bail!("coupled F16 tensor extent is outside the admitted source");
	}
	Ok(Extent { start, length })
}

fn copy_overlap(target: &mut [u8], extent: &Extent, chunk: &[u8], position: u64) -> usize {
	let left = position.max(extent.start);
	let right = (position + chunk.len() as u64).min(extent.start + extent.length as u64);
	if left >= right {
		return 0;
	}
	let count = (right - left) as usize;
	target[(left - extent.start) as usize..(right - extent.start) as usize]
		.copy_from_slice(&chunk[(left - position) as usize..(right - position) as usize]);
	count
}

fn hash_overlap(hash: &mut Sha256, chunk: &[u8], position: u64, start: u64, end: u64) {
	let left = position.max(start);
	let right = (position + chunk.len() as u64).min(end);
	if left < right {
		hash.update(&chunk[(left - position) as usize..(right - position) as usize]);
	}
}

pub(super) async fn capture(
	params: &CoupledF16EvaluationParams,
	shape: Shape,
	file: &mut tokio::fs::File,
	deadline: Instant,
) -> Result<CapturedHead> {
	check_deadline(deadline)?;
	let before = file.metadata().await?;
	if !before.is_file() || !(9..=MAX_MODEL_BYTES).contains(&before.len()) {
		bail!("coupled F16 evaluation requires a regular checkpoint within 2 GiB");
	}
	let version = rea_model::observed_version(&before)?;
	file.seek(std::io::SeekFrom::Start(0)).await?;
	let mut first = [0u8; 9];
	file.read_exact(&mut first).await?;
	let header_length = u64::from_le_bytes(first[..8].try_into()?);
	if !(1..=MAX_HEADER_BYTES).contains(&header_length)
		|| header_length > before.len() - 8
		|| first[8] != b'{'
	{
		bail!("coupled F16 evaluation requires the bounded proposal header profile");
	}
	let prefix = header_length + 8;
	// The existing parser's inherited descriptor has completed before our seek.
	let report = rea_model::inspect_snapshot_directory(file).await?;
	let tensors = report["result"]["tensors"]
		.as_array()
		.ok_or_else(|| anyhow!("coupled F16 directory is missing tensors"))?;
	let metadata = report["result"]["metadata"]
		.as_array()
		.ok_or_else(|| anyhow!("coupled F16 directory is missing metadata"))?;
	if report["format"] != "safetensors"
		|| report["byte_order"] != "little"
		|| report["unknown_storage_count"] != 0
		|| report["source"]["size_bytes"].as_u64() != Some(before.len())
		|| report["source"]["header_bytes"].as_u64() != Some(prefix)
		|| report["tensor_data_offset"].as_u64() != Some(prefix)
		|| report["source"]["observed_version"].as_str() != Some(version.as_str())
		|| !(1..=256).contains(&tensors.len())
		|| metadata.len() > 64
		|| tensors.iter().any(|tensor| {
			tensor["storage_length_verified"] != true
				|| !tensor["name"]
					.as_str()
					.is_some_and(|name| !name.is_empty() && name.len() <= 1024)
		}) || metadata.iter().any(|row| {
		!row["key"]
			.as_str()
			.is_some_and(|key| !key.is_empty() && key.len() <= 1024)
			|| !row["value"]
				.as_str()
				.is_some_and(|value| value.len() <= 4096)
	}) {
		bail!("coupled F16 directory differs from the bound proposal profile");
	}
	let weight_binding = &params.proposal.members[shape.weight_member].binding;
	let bias_binding = &params.proposal.members[shape.bias_member].binding;
	let weight = extent(
		&report,
		weight_binding,
		shape.outputs * shape.columns * 2,
		prefix,
		before.len(),
	)?;
	let bias = extent(
		&report,
		bias_binding,
		shape.outputs * 2,
		prefix,
		before.len(),
	)?;
	if weight.start < bias.start + bias.length as u64
		&& bias.start < weight.start + weight.length as u64
	{
		bail!("coupled F16 W and b extents overlap");
	}
	let mut weight_bytes = vec![0; weight.length];
	let mut bias_bytes = vec![0; bias.length];
	let mut weight_copied = 0usize;
	let mut bias_copied = 0usize;
	let mut source_hash = Sha256::new();
	let mut prefix_hash = Sha256::new();
	let mut json_header_hash = Sha256::new();
	let mut buffer = vec![0u8; STREAM_BYTES];
	let mut position = 0u64;
	file.seek(std::io::SeekFrom::Start(0)).await?;
	while position < before.len() {
		check_deadline(deadline)?;
		let count = (before.len() - position).min(buffer.len() as u64) as usize;
		file.read_exact(&mut buffer[..count]).await?;
		let chunk = &buffer[..count];
		source_hash.update(chunk);
		hash_overlap(&mut prefix_hash, chunk, position, 0, prefix);
		hash_overlap(&mut json_header_hash, chunk, position, 8, prefix);
		weight_copied += copy_overlap(&mut weight_bytes, &weight, chunk, position);
		bias_copied += copy_overlap(&mut bias_bytes, &bias, chunk, position);
		position += count as u64;
	}
	let after = file.metadata().await?;
	let raw_prefix_sha256 = rea_model::digest_hex(&prefix_hash.finalize());
	if rea_model::observed_version(&after)? != version
		|| rea_model::digest_hex(&source_hash.finalize()) != params.proposal.source_sha256
		|| report["source"]["header_sha256"].as_str() != Some(raw_prefix_sha256.as_str())
		|| weight_copied != weight.length
		|| bias_copied != bias.length
		|| sha(&weight_bytes) != weight_binding.payload_sha256
		|| sha(&bias_bytes) != bias_binding.payload_sha256
	{
		bail!("coupled F16 second capture differs from its complete source or tensor commitments");
	}
	check_deadline(deadline)?;
	Ok(CapturedHead {
		source_size_bytes: before.len(),
		observed_version: version,
		raw_prefix_sha256,
		json_header_sha256: rea_model::digest_hex(&json_header_hash.finalize()),
		weight_bytes,
		bias_bytes,
		weight_offset: weight.start,
		bias_offset: bias.start,
	})
}

/// Every finite binary16 value is exactly representable as binary32.
/// This is a decoder for evaluation, never a replacement-byte encoder.
pub(super) fn decode(bytes: &[u8]) -> Result<Vec<f32>> {
	if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
		bail!("coupled F16 coefficients must contain complete binary16 values");
	}
	bytes
		.as_chunks::<2>()
		.0
		.iter()
		.map(|bytes| {
			let bits = u16::from_le_bytes(*bytes);
			let sign = u32::from(bits & 0x8000) << 16;
			let exponent = u32::from((bits >> 10) & 31);
			let mantissa = u32::from(bits & 1023);
			let magnitude = match exponent {
				31 => {
					bail!("coupled F16 evaluation requires every selected coefficient to be finite")
				}
				0 if mantissa == 0 => 0,
				0 => {
					let leading = 31 - mantissa.leading_zeros();
					((leading + 103) << 23) | ((mantissa ^ (1 << leading)) << (23 - leading))
				}
				_ => ((exponent + 112) << 23) | (mantissa << 13),
			};
			Ok(f32::from_bits(sign | magnitude))
		})
		.collect()
}

pub(super) fn apply(bytes: &mut [u8], edits: &[weight_tensor::ExactElementEdit]) -> Result<()> {
	for edit in edits {
		let at = usize::try_from(edit.index)?
			.checked_mul(2)
			.ok_or_else(|| anyhow!("coupled F16 edit offset overflow"))?;
		let end = at
			.checked_add(2)
			.ok_or_else(|| anyhow!("coupled F16 edit end overflow"))?;
		let target = bytes
			.get_mut(at..end)
			.ok_or_else(|| anyhow!("coupled F16 edit is outside the selected tensor"))?;
		let expected = weight_tensor::unhex(&edit.expected_hex)?;
		let replacement = weight_tensor::unhex(&edit.replacement_hex)?;
		if expected.len() != 2 || replacement.len() != 2 || target != expected.as_slice() {
			bail!("coupled F16 exact edit differs from the captured original bytes");
		}
		target.copy_from_slice(&replacement);
	}
	Ok(())
}
