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

//! Same-stream whole-file, header, read-set and candidate commitments.
//! The existing model parser owns directory validation. No path or file is created.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::super::{rea_model, weight_tensor};
use super::{hex, F16ProposalParams, ReadSetIdentity};

const MAX_MODEL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_HEADER_BYTES: u64 = 256 * 1024;
const MAX_TENSORS: usize = 256;
const STREAM_BYTES: usize = 1024 * 1024;

/// Private and not deserializable. Only the checked descriptor stream constructs it.
pub(super) struct Capture {
	pub source_size_bytes: u64,
	pub observed_version: String,
	pub raw_prefix_sha256: String,
	pub json_header_sha256: String,
	pub candidate_sha256: String,
	pub read_set: Vec<ReadSetIdentity>,
}

struct Change {
	file_offset: u64,
	expected: [u8; 2],
	replacement: [u8; 2],
}

fn checked_directory(report: &Value, size: u64, prefix: u64, version: &str) -> Result<()> {
	let tensors = report["result"]["tensors"]
		.as_array()
		.ok_or_else(|| anyhow!("missing directory"))?;
	let metadata = report["result"]["metadata"]
		.as_array()
		.ok_or_else(|| anyhow!("missing metadata"))?;
	if report["format"] != "safetensors"
		|| report["byte_order"] != "little"
		|| report["unknown_storage_count"] != 0
		|| report["source"]["size_bytes"].as_u64() != Some(size)
		|| report["source"]["header_bytes"].as_u64() != Some(prefix)
		|| report["tensor_data_offset"].as_u64() != Some(prefix)
		|| report["source"]["observed_version"].as_str() != Some(version)
		|| !(1..=MAX_TENSORS).contains(&tensors.len())
		|| metadata.len() > 64
	{
		bail!("F16 source requires a complete bounded verified safetensors directory");
	}
	for tensor in tensors {
		if !tensor["name"]
			.as_str()
			.is_some_and(|name| !name.is_empty() && name.len() <= 1024)
			|| tensor["storage_length_verified"] != true
		{
			bail!("F16 source tensor directory exceeds the bounded profile");
		}
	}
	for row in metadata {
		if !row["key"]
			.as_str()
			.is_some_and(|key| !key.is_empty() && key.len() <= 1024)
			|| row["value"].as_str().is_none_or(|value| value.len() > 4096)
		{
			bail!("F16 source metadata exceeds the bounded profile");
		}
	}
	Ok(())
}

fn selected(
	params: &F16ProposalParams,
	report: &Value,
) -> Result<(Vec<ReadSetIdentity>, Vec<Change>)> {
	let tensors = report["result"]["tensors"]
		.as_array()
		.ok_or_else(|| anyhow!("missing directory"))?;
	let mut read_set = Vec::with_capacity(params.members.len());
	let mut changes = Vec::new();
	for member in &params.members {
		let binding = &member.binding;
		let tensor = tensors
			.iter()
			.find(|tensor| tensor["name"].as_str() == Some(binding.name.as_str()))
			.ok_or_else(|| anyhow!("selected F16 tensor is missing"))?;
		let shape: Vec<_> = binding.shape.iter().map(u64::to_string).collect();
		if tensor["dtype"] != "F16" || tensor["shape"] != serde_json::to_value(shape)? {
			bail!("selected F16 tensor dtype or shape differs from its binding");
		}
		let start = tensor["file_offset"]
			.as_u64()
			.ok_or_else(|| anyhow!("missing tensor offset"))?;
		let length = tensor["byte_length"]
			.as_u64()
			.ok_or_else(|| anyhow!("missing tensor length"))?;
		let size = report["source"]["size_bytes"]
			.as_u64()
			.ok_or_else(|| anyhow!("missing source size"))?;
		let prefix = report["source"]["header_bytes"]
			.as_u64()
			.ok_or_else(|| anyhow!("missing header extent"))?;
		if start < prefix
			|| start > size
			|| !(2..=size - start).contains(&length)
			|| !length.is_multiple_of(2)
		{
			bail!("selected F16 tensor extent is invalid or empty");
		}
		if !member.edits.is_empty() {
			let patch = weight_tensor::prepare(
				&weight_tensor::PatchTensorParams {
					path: params.path.clone(),
					expected_sha256: params.source_sha256.clone(),
					tensor_name: binding.name.clone(),
					edits: member.edits.clone(),
				},
				&json!({"format":"safetensors", "source":report["source"], "result":{"tensor":tensor}}),
			)?;
			for change in patch.changes {
				changes.push(Change {
					file_offset: change.file_offset,
					expected: weight_tensor::unhex(&change.expected_hex)?
						.as_slice()
						.try_into()?,
					replacement: weight_tensor::unhex(&change.replacement_hex)?
						.as_slice()
						.try_into()?,
				});
			}
		}
		read_set.push(ReadSetIdentity {
			binding: binding.clone(),
			role: member.role,
			file_offset: start,
			byte_length: length,
			checked_elements: member.edits.len(),
		});
	}
	changes.sort_unstable_by_key(|change| change.file_offset);
	if changes
		.windows(2)
		.any(|pair| pair[0].file_offset + 2 > pair[1].file_offset)
	{
		bail!("F16 exact byte changes overlap");
	}
	Ok((read_set, changes))
}

fn update_range(hash: &mut Sha256, bytes: &[u8], position: u64, start: u64, end: u64) {
	let left = position.max(start);
	let right = (position + bytes.len() as u64).min(end);
	if left < right {
		hash.update(&bytes[(left - position) as usize..(right - position) as usize]);
	}
}

pub(super) async fn capture(
	params: &F16ProposalParams,
	file: &mut tokio::fs::File,
) -> Result<Capture> {
	let before = file.metadata().await?;
	if !before.is_file() || !(9..=MAX_MODEL_BYTES).contains(&before.len()) {
		bail!("F16 proposals require a regular checkpoint within the existing 2 GiB owner cap");
	}
	let version = rea_model::observed_version(&before)?;
	file.seek(std::io::SeekFrom::Start(0)).await?;
	let mut first = [0_u8; 9];
	file.read_exact(&mut first).await?;
	let header_length = u64::from_le_bytes(first[..8].try_into()?);
	if !(1..=MAX_HEADER_BYTES).contains(&header_length)
		|| first[8] != b'{'
		|| header_length > before.len() - 8
	{
		bail!("F16 source requires a complete safetensors header of at most 256 KiB");
	}
	let prefix = 8 + header_length;
	// The existing parser returns before this descriptor is sought again. Its
	// inherited clone is never concurrently used by the full-file stream below.
	let report = rea_model::inspect_snapshot_directory(file).await?;
	checked_directory(&report, before.len(), prefix, &version)?;
	let expected_prefix = report["source"]["header_sha256"]
		.as_str()
		.ok_or_else(|| anyhow!("missing header SHA"))?;
	let (read_set, changes) = selected(params, &report)?;
	let mut tensor_hashes: Vec<_> = read_set.iter().map(|_| Sha256::new()).collect();
	let mut source_hash = Sha256::new();
	let mut candidate_hash = Sha256::new();
	let mut prefix_hash = Sha256::new();
	let mut json_header_hash = Sha256::new();
	let mut buffer = vec![0_u8; STREAM_BYTES];
	let mut position = 0_u64;
	let mut change_index = 0usize;
	file.seek(std::io::SeekFrom::Start(0)).await?;
	while position < before.len() {
		let count = (before.len() - position).min(buffer.len() as u64) as usize;
		file.read_exact(&mut buffer[..count]).await?;
		let bytes = &buffer[..count];
		let end = position + count as u64;
		source_hash.update(bytes);
		update_range(&mut prefix_hash, bytes, position, 0, prefix);
		update_range(&mut json_header_hash, bytes, position, 8, prefix);
		for (tensor, hash) in read_set.iter().zip(&mut tensor_hashes) {
			update_range(
				hash,
				bytes,
				position,
				tensor.file_offset,
				tensor.file_offset + tensor.byte_length,
			);
		}
		let mut cursor = 0usize;
		while let Some(change) = changes.get(change_index) {
			if change.file_offset >= end {
				break;
			}
			let left = change.file_offset.max(position);
			let right = (change.file_offset + 2).min(end);
			let range = (left - position) as usize..(right - position) as usize;
			let element =
				(left - change.file_offset) as usize..(right - change.file_offset) as usize;
			if bytes[range.clone()] != change.expected[element.clone()] {
				bail!("F16 expected bytes differ from the full-file source stream");
			}
			candidate_hash.update(&bytes[cursor..range.start]);
			candidate_hash.update(&change.replacement[element]);
			cursor = range.end;
			if change.file_offset + 2 > end {
				break;
			}
			change_index += 1;
		}
		candidate_hash.update(&bytes[cursor..]);
		position = end;
	}
	let after = file.metadata().await?;
	if rea_model::observed_version(&after)? != version || change_index != changes.len() {
		bail!("F16 source changed or selected bytes were not completely observed");
	}
	let raw_prefix_sha256 = hex(&prefix_hash.finalize());
	if hex(&source_hash.finalize()) != params.source_sha256 || raw_prefix_sha256 != expected_prefix
	{
		bail!("F16 complete source or parser header differs from the same-stream commitment");
	}
	for (tensor, hash) in read_set.iter().zip(tensor_hashes) {
		if hex(&hash.finalize()) != tensor.binding.payload_sha256 {
			bail!("F16 read-set tensor payload differs from its complete commitment");
		}
	}
	Ok(Capture {
		source_size_bytes: before.len(),
		observed_version: version,
		raw_prefix_sha256,
		json_header_sha256: hex(&json_header_hash.finalize()),
		candidate_sha256: hex(&candidate_hash.finalize()),
		read_set,
	})
}
