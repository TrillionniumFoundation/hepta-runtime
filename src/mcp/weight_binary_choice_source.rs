// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Capture the actual F32 head and all protected-byte commitments from one admitted descriptor.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::{
	check_deadline, rea_model, sha, BinaryChoiceParams, CheckpointBinding, SourceEvidence,
};

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_PREFIX_BYTES: u64 = 256 * 1024 + 8;
const STREAM_BYTES: usize = 1024 * 1024;

pub(super) struct Captured {
	pub weights: Vec<f32>,
	pub bias: Vec<f32>,
	pub evidence: SourceEvidence,
}

struct Extent {
	start: u64,
	length: usize,
}

fn extent(report: &Value, name: &str, shape: &[usize], size: u64, prefix: u64) -> Result<Extent> {
	let tensor = &report["result"]["tensor"];
	let count = shape.iter().product::<usize>();
	let length = count * 4;
	let start = tensor["file_offset"]
		.as_u64()
		.ok_or_else(|| anyhow!("binary-choice tensor has no exact byte offset"))?;
	let shape: Vec<_> = shape.iter().map(usize::to_string).collect();
	if report["format"] != "safetensors"
		|| report["byte_order"] != "little"
		|| tensor["name"] != name
		|| tensor["dtype"] != "F32"
		|| tensor["shape"] != json!(shape)
		|| tensor["storage_length_verified"] != true
		|| tensor["byte_length"].as_u64() != Some(length as u64)
		|| start < prefix
		|| start > size
		|| length as u64 > size - start
	{
		bail!("binary-choice head must be the exact named F32 [2,width] weight and F32 [2] bias");
	}
	Ok(Extent { start, length })
}

fn hash_overlap(hash: &mut Sha256, chunk: &[u8], position: u64, start: u64, end: u64) {
	let left = position.max(start);
	let right = (position + chunk.len() as u64).min(end);
	if left < right {
		hash.update(&chunk[(left - position) as usize..(right - position) as usize]);
	}
}

fn copy_overlap(target: &mut [u8], extent: &Extent, chunk: &[u8], position: u64) -> usize {
	let left = position.max(extent.start);
	let right = (position + chunk.len() as u64).min(extent.start + extent.length as u64);
	if left >= right {
		return 0;
	}
	target[(left - extent.start) as usize..(right - extent.start) as usize]
		.copy_from_slice(&chunk[(left - position) as usize..(right - position) as usize]);
	(right - left) as usize
}

fn decode(bytes: &[u8]) -> Result<Vec<f32>> {
	if !bytes.len().is_multiple_of(4) {
		bail!("binary-choice F32 capture has an incomplete element");
	}
	let mut values = Vec::with_capacity(bytes.len() / 4);
	for bytes in bytes.chunks_exact(4) {
		let value = f32::from_le_bytes(bytes.try_into()?);
		if !value.is_finite() {
			bail!("binary-choice actual head contains a nonfinite F32 coefficient");
		}
		values.push(value);
	}
	Ok(values)
}

pub(super) async fn capture(
	params: &BinaryChoiceParams,
	binding: &CheckpointBinding,
	file: &mut tokio::fs::File,
	columns: usize,
	deadline: Instant,
) -> Result<Captured> {
	check_deadline(deadline)?;
	let before = file.metadata().await?;
	if !before.is_file() || !(9..=MAX_FILE_BYTES).contains(&before.len()) {
		bail!("binary-choice source must be a regular checkpoint within 2 GiB");
	}
	let version = rea_model::observed_version(&before)?;
	let weight_report = rea_model::inspect_tensor_descriptor(file, &params.weight_tensor).await?;
	check_deadline(deadline)?;
	let bias_report = rea_model::inspect_tensor_descriptor(file, &params.bias_tensor).await?;
	check_deadline(deadline)?;
	let prefix = weight_report["source"]["header_bytes"]
		.as_u64()
		.filter(|prefix| (9..=MAX_PREFIX_BYTES).contains(prefix) && *prefix <= before.len())
		.ok_or_else(|| anyhow!("binary-choice head requires a bounded safetensors header"))?;
	for report in [&weight_report, &bias_report] {
		if report["source"]["size_bytes"].as_u64() != Some(before.len())
			|| report["source"]["observed_version"].as_str() != Some(version.as_str())
			|| report["source"]["header_bytes"].as_u64() != Some(prefix)
			|| report["source"]["header_sha256"] != weight_report["source"]["header_sha256"]
		{
			bail!("binary-choice tensor descriptors differ from their admitted source identity");
		}
	}
	let weight = extent(
		&weight_report,
		&params.weight_tensor,
		&[2, columns],
		before.len(),
		prefix,
	)?;
	let bias = extent(
		&bias_report,
		&params.bias_tensor,
		&[2],
		before.len(),
		prefix,
	)?;
	if weight.start < bias.start + bias.length as u64
		&& bias.start < weight.start + weight.length as u64
	{
		bail!("binary-choice weight and bias extents overlap");
	}
	let mut weight_bytes = vec![0_u8; weight.length];
	let mut bias_bytes = vec![0_u8; bias.length];
	let mut weight_copied = 0;
	let mut bias_copied = 0;
	let mut complete = Sha256::new();
	let mut header = Sha256::new();
	let mut protected = Sha256::new();
	protected.update(b"hepta.weight.binary-choice-protected-bytes.v1\0");
	protected.update(before.len().to_le_bytes());
	protected.update(weight.start.to_le_bytes());
	protected.update((weight.length as u64).to_le_bytes());
	let mut buffer = vec![0_u8; STREAM_BYTES];
	let mut position = 0;
	file.seek(std::io::SeekFrom::Start(0)).await?;
	while position < before.len() {
		check_deadline(deadline)?;
		let count = (before.len() - position).min(buffer.len() as u64) as usize;
		file.read_exact(&mut buffer[..count]).await?;
		let chunk = &buffer[..count];
		complete.update(chunk);
		hash_overlap(&mut header, chunk, position, 0, prefix);
		// The bias, physical buffers, all other tensors and the complete raw header remain
		// protected. Only this one exact weight extent is excluded from the commitment.
		hash_overlap(&mut protected, chunk, position, 0, weight.start);
		hash_overlap(
			&mut protected,
			chunk,
			position,
			weight.start + weight.length as u64,
			before.len(),
		);
		weight_copied += copy_overlap(&mut weight_bytes, &weight, chunk, position);
		bias_copied += copy_overlap(&mut bias_bytes, &bias, chunk, position);
		position += count as u64;
	}
	let complete_sha256 = rea_model::digest_hex(&complete.finalize());
	let header_sha256 = rea_model::digest_hex(&header.finalize());
	let weight_payload_sha256 = sha(&weight_bytes);
	let bias_payload_sha256 = sha(&bias_bytes);
	let after = file.metadata().await?;
	#[cfg(unix)]
	super::rea_files::ensure_unchanged(&before, &after)?;
	if rea_model::observed_version(&after)? != version
		|| complete_sha256 != binding.complete_sha256
		|| weight_report["source"]["header_sha256"].as_str() != Some(header_sha256.as_str())
		|| weight_payload_sha256 != binding.weight_payload_sha256
		|| bias_payload_sha256 != binding.bias_payload_sha256
		|| weight_copied != weight.length
		|| bias_copied != bias.length
	{
		bail!(
			"binary-choice capture differs from its complete file, header or exact parameter commitments"
		);
	}
	check_deadline(deadline)?;
	Ok(Captured {
		weights: decode(&weight_bytes)?,
		bias: decode(&bias_bytes)?,
		evidence: SourceEvidence {
			complete_sha256,
			source_size_bytes: before.len(),
			observed_version: version,
			header_sha256,
			protected_bytes_sha256: rea_model::digest_hex(&protected.finalize()),
			weight_payload_sha256,
			bias_payload_sha256,
			weight_offset: weight.start,
			weight_length: weight.length,
			bias_offset: bias.start,
			complete_source_hash_passes: 1,
		},
	})
}
