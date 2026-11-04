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

//! Bounded, descriptor-only GGUF and safetensors directory parsing. Tensor
//! payloads are never retained with the directory. Unknown GGUF storage layouts
//! remain unknown even when neighboring offsets appear to suggest a size.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use super::{digest_hex, observed_version, Collection, MAX_HEADER_BYTES, MAX_READ_BYTES};

const MAX_ROWS: usize = 100_000;
const MAX_STRING_BYTES: usize = 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 32 * 1024 * 1024;
const MAX_VALUE_ITEMS: usize = 1_000_000;
const ARRAY_PREVIEW_ITEMS: usize = 8;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum WorkerRequest {
	/// Complete bounded index for a retained snapshot; never returned directly over MCP.
	Directory,
	Inspect {
		collection: Collection,
		offset: usize,
		limit: usize,
	},
	Read {
		tensor_name: Option<String>,
		offset: u64,
		length: usize,
	},
}

impl WorkerRequest {
	pub(super) fn response_limit(&self) -> usize {
		match self {
			Self::Directory => super::MAX_INDEX_RESPONSE_BYTES,
			_ => super::MAX_RESPONSE_BYTES,
		}
	}
}

#[derive(Debug, Serialize)]
struct Tensor {
	name: String,
	dtype: String,
	type_id: Option<u32>,
	// Decimal strings preserve dimensions and products above JavaScript's exact
	// integer range; file offsets are constrained separately at admission.
	shape: Vec<String>,
	elements: String,
	file_offset: u64,
	byte_length: Option<u64>,
	storage_length_verified: bool,
}

#[derive(Debug)]
struct Directory {
	format: &'static str,
	version: Option<u32>,
	byte_order: &'static str,
	header_bytes: u64,
	header_sha256: String,
	data_offset: u64,
	tensors: Vec<Tensor>,
	metadata: Vec<Value>,
	limitations: Vec<String>,
}

struct HeaderReader<'a> {
	file: &'a mut File,
	file_size: u64,
	position: u64,
	hash: Sha256,
	little: bool,
	value_items: usize,
}

impl<'a> HeaderReader<'a> {
	fn new(file: &'a mut File, file_size: u64) -> Result<Self> {
		file.seek(SeekFrom::Start(0))?;
		Ok(Self {
			file,
			file_size,
			position: 0,
			hash: Sha256::new(),
			little: true,
			value_items: 0,
		})
	}

	fn admit(&self, length: usize) -> Result<u64> {
		let end = self
			.position
			.checked_add(u64::try_from(length)?)
			.ok_or_else(|| anyhow!("model header offset overflow"))?;
		if end > self.file_size {
			bail!("model header extends beyond admitted file size");
		}
		if end > MAX_HEADER_BYTES {
			bail!("model header exceeds this reader's {MAX_HEADER_BYTES} byte limit");
		}
		Ok(end)
	}

	fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
		let end = self.admit(N)?;
		let mut bytes = [0_u8; N];
		self.file
			.read_exact(&mut bytes)
			.context("truncated model header")?;
		self.hash.update(bytes);
		self.position = end;
		Ok(bytes)
	}

	fn bytes(&mut self, length: usize) -> Result<Vec<u8>> {
		let end = self.admit(length)?;
		let mut bytes = Vec::new();
		bytes.try_reserve_exact(length)?;
		bytes.resize(length, 0);
		self.file
			.read_exact(&mut bytes)
			.context("truncated model header")?;
		self.hash.update(&bytes);
		self.position = end;
		Ok(bytes)
	}

	fn u8(&mut self) -> Result<u8> {
		Ok(self.fixed::<1>()?[0])
	}
	fn u16(&mut self) -> Result<u16> {
		let b = self.fixed()?;
		Ok(if self.little {
			u16::from_le_bytes(b)
		} else {
			u16::from_be_bytes(b)
		})
	}
	fn u32(&mut self) -> Result<u32> {
		let b = self.fixed()?;
		Ok(if self.little {
			u32::from_le_bytes(b)
		} else {
			u32::from_be_bytes(b)
		})
	}
	fn u64(&mut self) -> Result<u64> {
		let b = self.fixed()?;
		Ok(if self.little {
			u64::from_le_bytes(b)
		} else {
			u64::from_be_bytes(b)
		})
	}
	fn string(&mut self) -> Result<String> {
		let length = usize::try_from(self.u64()?)?;
		if length > MAX_STRING_BYTES {
			bail!("GGUF string exceeds the {MAX_STRING_BYTES} byte limit");
		}
		String::from_utf8(self.bytes(length)?).context("GGUF string is not UTF-8")
	}
	fn digest(&self) -> String {
		digest_hex(&self.hash.clone().finalize())
	}

	fn value(&mut self, kind: u32, depth: usize) -> Result<Value> {
		if depth > 32 || self.value_items >= MAX_VALUE_ITEMS {
			bail!("GGUF metadata exceeds nesting or item budget");
		}
		self.value_items += 1;
		Ok(match kind {
			0 => json!(self.u8()?),
			1 => json!(self.u8()? as i8),
			2 => json!(self.u16()?),
			3 => json!(self.u16()? as i16),
			4 => json!(self.u32()?),
			5 => json!(self.u32()? as i32),
			6 => float_value(f64::from(f32::from_bits(self.u32()?))),
			7 => match self.u8()? {
				0 => json!(false),
				1 => json!(true),
				_ => bail!("GGUF boolean must be encoded as zero or one"),
			},
			8 => json!(self.string()?),
			9 => {
				let element_type = self.u32()?;
				if element_type > 12 {
					bail!("unsupported GGUF metadata array type {element_type}");
				}
				let count = usize::try_from(self.u64()?)?;
				if count > MAX_VALUE_ITEMS.saturating_sub(self.value_items) {
					bail!("GGUF metadata array exceeds item budget");
				}
				let mut preview = Vec::new();
				for index in 0..count {
					let value = self.value(element_type, depth + 1)?;
					if index < ARRAY_PREVIEW_ITEMS {
						preview.push(value);
					}
				}
				json!({"element_type_id":element_type,"count":count,
					"preview":preview,"preview_truncated":count > ARRAY_PREVIEW_ITEMS})
			}
			10 => json!(self.u64()?.to_string()),
			11 => json!((self.u64()? as i64).to_string()),
			12 => float_value(f64::from_bits(self.u64()?)),
			_ => bail!("unsupported GGUF metadata value type {kind}; extent is unknown"),
		})
	}
}

fn float_value(value: f64) -> Value {
	if value.is_nan() {
		json!("NaN")
	} else if value == f64::INFINITY {
		json!("Infinity")
	} else if value == f64::NEG_INFINITY {
		json!("-Infinity")
	} else if value == 0.0 && value.is_sign_negative() {
		json!("-0")
	} else {
		json!(value)
	}
}

fn retain_budget(used: &mut usize, bytes: usize) -> Result<()> {
	*used = used
		.checked_add(bytes)
		.ok_or_else(|| anyhow!("model directory budget overflow"))?;
	if *used > MAX_RETAINED_BYTES {
		bail!("model retained directory exceeds {MAX_RETAINED_BYTES} byte budget");
	}
	Ok(())
}

fn shape_product(shape: &[u64]) -> Result<u64> {
	shape.iter().try_fold(1_u64, |product, dimension| {
		product
			.checked_mul(*dimension)
			.ok_or_else(|| anyhow!("model tensor shape product overflows u64"))
	})
}

fn parse_gguf(mut reader: HeaderReader<'_>) -> Result<Directory> {
	let version_bytes = reader.fixed::<4>()?;
	let little_version = u32::from_le_bytes(version_bytes);
	let big_version = u32::from_be_bytes(version_bytes);
	let version = if matches!(little_version, 2 | 3) {
		little_version
	} else if matches!(big_version, 2 | 3) {
		reader.little = false;
		big_version
	} else {
		bail!("only GGUF versions 2 and 3 are supported");
	};
	let tensor_count = usize::try_from(reader.u64()?)?;
	let metadata_count = usize::try_from(reader.u64()?)?;
	if tensor_count > MAX_ROWS || metadata_count > MAX_ROWS {
		bail!("GGUF declared directory count exceeds {MAX_ROWS} rows");
	}
	let mut retained = 0;
	let mut metadata = Vec::new();
	let mut names = HashSet::new();
	let mut alignment = 32_u64;
	for _ in 0..metadata_count {
		let key = reader.string()?;
		if !names.insert(key.clone()) {
			bail!("duplicate GGUF metadata key");
		}
		let kind = reader.u32()?;
		let value = reader.value(kind, 0)?;
		if key == "general.alignment" {
			if kind != 4 {
				bail!("GGUF general.alignment must have uint32 type");
			}
			alignment = value
				.as_u64()
				.ok_or_else(|| anyhow!("invalid GGUF alignment"))?;
			if !alignment.is_power_of_two() || alignment > 1024 * 1024 {
				bail!("GGUF alignment must be a power of two within 1 MiB");
			}
		}
		let row = json!({"key":key,"type_id":kind,"value":value});
		retain_budget(&mut retained, serde_json::to_vec(&row)?.len() + 64)?;
		metadata.push(row);
	}
	let mut tensors = Vec::new();
	names.clear();
	for _ in 0..tensor_count {
		let name = reader.string()?;
		if !names.insert(name.clone()) {
			bail!("duplicate GGUF tensor name");
		}
		let dimensions = reader.u32()?;
		if !(1..=4).contains(&dimensions) {
			bail!("GGUF tensors must have one to four dimensions");
		}
		let shape = (0..dimensions)
			.map(|_| reader.u64())
			.collect::<Result<Vec<_>>>()?;
		let elements = shape_product(&shape)?;
		let type_id = reader.u32()?;
		let relative_offset = reader.u64()?;
		if relative_offset % alignment != 0 {
			bail!("GGUF tensor offset violates declared alignment");
		}
		// Quantized layouts depend on producer/version details. This first native
		// reader verifies only invariant scalar layouts, never guessed block sizes.
		let (dtype, scalar_bytes) = match type_id {
			0 => ("F32".to_string(), Some(4_u64)),
			1 => ("F16".to_string(), Some(2_u64)),
			_ => (format!("GGML_TYPE_{type_id}"), None),
		};
		let byte_length = if elements == 0 {
			Some(0)
		} else {
			scalar_bytes
				.map(|size| {
					elements
						.checked_mul(size)
						.ok_or_else(|| anyhow!("GGUF tensor storage length overflow"))
				})
				.transpose()?
		};
		retain_budget(&mut retained, name.len() * 2 + 256)?;
		tensors.push(Tensor {
			name,
			dtype,
			type_id: Some(type_id),
			shape: shape.iter().map(u64::to_string).collect(),
			elements: elements.to_string(),
			file_offset: relative_offset,
			byte_length,
			storage_length_verified: byte_length.is_some(),
		});
	}
	let header_bytes = reader.position;
	let aligned = header_bytes
		.checked_add(alignment - 1)
		.ok_or_else(|| anyhow!("GGUF header alignment overflow"))?
		& !(alignment - 1);
	let data_offset = if tensors.is_empty() && reader.file_size == header_bytes {
		header_bytes
	} else {
		aligned
	};
	if data_offset > reader.file_size {
		bail!("GGUF tensor data alignment is outside the admitted file");
	}
	for tensor in &mut tensors {
		tensor.file_offset = data_offset
			.checked_add(tensor.file_offset)
			.ok_or_else(|| anyhow!("GGUF tensor absolute offset overflow"))?;
		if tensor.file_offset > reader.file_size {
			bail!("GGUF tensor offset is outside the admitted file");
		}
		if let Some(length) = tensor.byte_length {
			if length > reader.file_size - tensor.file_offset {
				bail!("GGUF tensor range extends beyond the admitted file");
			}
		}
	}
	let mut ranges: Vec<_> = tensors.iter().collect();
	ranges.sort_by_key(|row| (row.file_offset, row.byte_length.unwrap_or(u64::MAX)));
	let mut known_end = data_offset;
	for row in ranges {
		if row.file_offset < known_end {
			bail!("GGUF tensor declaration overlaps a verified tensor extent");
		}
		known_end = row.file_offset + row.byte_length.unwrap_or(0);
	}
	let unknown = tensors.iter().any(|row| row.byte_length.is_none());
	let mut limitations = vec![
		"GGUF dimensions retain their declared fastest-first order.".to_string(),
		"Only F32/F16 and zero-element GGUF storage lengths are verified; other layouts are unknown.".to_string(),
	];
	if unknown {
		limitations.push("Unknown quantized storage layouts are not inferred from adjacent offsets; tensor-scoped reads of those rows are refused.".to_string());
	}
	Ok(Directory {
		format: "gguf",
		version: Some(version),
		byte_order: if reader.little { "little" } else { "big" },
		header_bytes,
		header_sha256: reader.digest(),
		data_offset,
		tensors,
		metadata,
		limitations,
	})
}

// This dtype table follows the existing native REA preview. The REA-derived
// type mapping retains its upstream attribution in LICENSES/REA-MIT.txt.
fn safetensors_bits(dtype: &str) -> Option<u64> {
	match dtype {
		"F4" => Some(4),
		"F6_E2M3" | "F6_E3M2" => Some(6),
		"BOOL" | "I8" | "U8" | "F8_E5M2" | "F8_E4M3" | "F8_E8M0" | "F8_E4M3FNUZ"
		| "F8_E5M2FNUZ" => Some(8),
		"I16" | "U16" | "F16" | "BF16" => Some(16),
		"I32" | "U32" | "F32" => Some(32),
		"I64" | "U64" | "F64" | "C64" => Some(64),
		_ => None,
	}
}

fn parse_safetensors(mut reader: HeaderReader<'_>, first: [u8; 4]) -> Result<Directory> {
	let tail = reader.fixed::<4>()?;
	let length = u64::from_le_bytes([
		first[0], first[1], first[2], first[3], tail[0], tail[1], tail[2], tail[3],
	]);
	if length == 0 || length > MAX_HEADER_BYTES - 8 {
		bail!("unsupported model format or safetensors header exceeds native budget");
	}
	let bytes = reader.bytes(usize::try_from(length)?)?;
	if bytes.first() != Some(&b'{') {
		bail!("unsupported model format: safetensors JSON must start with an object");
	}
	let document = super::super::rea_evidence::parse_unique_json(&bytes)?;
	let object = document
		.as_object()
		.ok_or_else(|| anyhow!("safetensors header must be an object"))?;
	if object.len() > MAX_ROWS + 1 {
		bail!("safetensors tensor count exceeds {MAX_ROWS} rows");
	}
	let data_offset = reader.position;
	let payload_bytes = reader.file_size - data_offset;
	let mut tensors = Vec::new();
	let mut metadata = Vec::new();
	let mut retained = 0;
	for (name, value) in object {
		if name == "__metadata__" {
			if value.is_null() {
				continue;
			}
			let values = value
				.as_object()
				.ok_or_else(|| anyhow!("safetensors __metadata__ must be a string map"))?;
			if values.len() > MAX_ROWS {
				bail!("safetensors metadata count exceeds {MAX_ROWS} rows");
			}
			for (key, item) in values {
				let text = item
					.as_str()
					.ok_or_else(|| anyhow!("safetensors metadata value is not a string"))?;
				retain_budget(&mut retained, key.len() + text.len() + 128)?;
				metadata.push(json!({"key":key,"value":text}));
			}
			continue;
		}
		let entry = value
			.as_object()
			.ok_or_else(|| anyhow!("safetensors tensor declaration must be an object"))?;
		let dtype = entry
			.get("dtype")
			.and_then(Value::as_str)
			.ok_or_else(|| anyhow!("safetensors tensor is missing dtype"))?;
		let shape = entry
			.get("shape")
			.and_then(Value::as_array)
			.ok_or_else(|| anyhow!("safetensors tensor is missing shape"))?;
		if shape.len() > 32 {
			bail!("safetensors tensor exceeds this reader's 32-dimension limit");
		}
		let shape = shape
			.iter()
			.map(|value| {
				value
					.as_u64()
					.ok_or_else(|| anyhow!("safetensors shape dimension is not a u64 integer"))
			})
			.collect::<Result<Vec<_>>>()?;
		let elements = shape_product(&shape)?;
		let offsets = entry
			.get("data_offsets")
			.and_then(Value::as_array)
			.ok_or_else(|| anyhow!("safetensors tensor is missing data_offsets"))?;
		if offsets.len() != 2 {
			bail!("safetensors tensor requires exactly two offsets");
		}
		let start = offsets[0]
			.as_u64()
			.ok_or_else(|| anyhow!("safetensors start offset is not a u64 integer"))?;
		let end = offsets[1]
			.as_u64()
			.ok_or_else(|| anyhow!("safetensors end offset is not a u64 integer"))?;
		if start > end || end > payload_bytes {
			bail!("safetensors tensor range is outside its payload");
		}
		let bits = safetensors_bits(dtype);
		if let Some(bits) = bits {
			let expected = elements
				.checked_mul(bits)
				.ok_or_else(|| anyhow!("safetensors tensor bit length overflows"))?;
			if expected % 8 != 0 || expected / 8 != end - start {
				bail!("safetensors tensor extent disagrees with dtype and shape");
			}
		}
		retain_budget(
			&mut retained,
			name.len() + dtype.len() + shape.len() * 24 + 256,
		)?;
		tensors.push(Tensor {
			name: name.clone(),
			dtype: dtype.to_string(),
			type_id: None,
			shape: shape.iter().map(u64::to_string).collect(),
			elements: elements.to_string(),
			file_offset: data_offset + start,
			byte_length: Some(end - start),
			storage_length_verified: bits.is_some(),
		});
	}
	let mut ranges: Vec<_> = tensors
		.iter()
		.map(|row| (row.file_offset, row.byte_length.unwrap_or(0)))
		.collect();
	ranges.sort_unstable();
	let mut cursor = data_offset;
	for (start, length) in ranges {
		if start != cursor {
			bail!("safetensors tensor directory has a gap or overlap");
		}
		cursor = start + length;
	}
	if cursor != reader.file_size {
		bail!("safetensors has unindexed trailing payload bytes");
	}
	Ok(Directory {
		format: "safetensors",
		version: None,
		byte_order: "little",
		header_bytes: reader.position,
		header_sha256: reader.digest(),
		data_offset,
		tensors,
		metadata,
		limitations: vec![
			"Unknown dtypes retain declared ranges without claiming shape-to-storage validation."
				.to_string(),
			"Tensor rows are ordered by name; shapes retain safetensors JSON order.".to_string(),
		],
	})
}

fn parse(file: &mut File, file_size: u64) -> Result<Directory> {
	let mut reader = HeaderReader::new(file, file_size)?;
	let first = reader.fixed::<4>()?;
	if &first == b"GGUF" {
		parse_gguf(reader)
	} else {
		parse_safetensors(reader, first)
	}
}

/// The same implementation is exercised by unit fixtures and the inherited-fd
/// worker. No path or runtime configuration is available to this parser.
pub(super) fn inspect_file(file: &mut File, request: &WorkerRequest) -> Result<Value> {
	let before = file.metadata()?;
	if !before.is_file() || before.len() > 9_007_199_254_740_991 {
		bail!("model input must be a regular file with exact JSON-safe byte offsets");
	}
	let observed_version = observed_version(&before)?;
	let directory = parse(file, before.len())?;
	let unknown = directory
		.tensors
		.iter()
		.filter(|row| !row.storage_length_verified)
		.count();
	let (operation, result) = match request {
		WorkerRequest::Directory => (
			"index_model_artifact",
			json!({"tensors": &directory.tensors, "metadata": &directory.metadata}),
		),
		WorkerRequest::Inspect {
			collection,
			offset,
			limit,
		} => {
			if !(1..=256).contains(limit) {
				bail!("model page limit must be between 1 and 256");
			}
			let total = match collection {
				Collection::Tensors => directory.tensors.len(),
				Collection::Metadata => directory.metadata.len(),
				Collection::Summary => 0,
			};
			if *offset > total {
				bail!("model page offset exceeds collection size");
			}
			let end = offset.saturating_add(*limit).min(total);
			let rows = match collection {
				Collection::Tensors => serde_json::to_value(&directory.tensors[*offset..end])?,
				Collection::Metadata => serde_json::to_value(&directory.metadata[*offset..end])?,
				Collection::Summary => json!([]),
			};
			(
				"inspect_model_artifact",
				json!({"collection":collection,"offset":offset,
				"limit":limit,"total":total,"next_offset":(end < total).then_some(end),"rows":rows}),
			)
		}
		WorkerRequest::Read {
			tensor_name,
			offset,
			length,
		} => {
			if !(1..=MAX_READ_BYTES).contains(length) {
				bail!("model read length must be between 1 and {MAX_READ_BYTES}");
			}
			let (start, extent, selected) = if let Some(name) = tensor_name {
				let tensor = directory
					.tensors
					.iter()
					.find(|row| &row.name == name)
					.ok_or_else(|| anyhow!("selected tensor does not exist"))?;
				let size = tensor.byte_length.ok_or_else(|| {
					anyhow!("selected GGUF tensor storage layout is unknown; tensor-scoped reads are refused")
				})?;
				(tensor.file_offset, size, serde_json::to_value(tensor)?)
			} else {
				(0, before.len(), Value::Null)
			};
			if *offset > extent || *length as u64 > extent - offset {
				bail!("model byte read would cross the selected file or tensor boundary");
			}
			let absolute = start
				.checked_add(*offset)
				.ok_or_else(|| anyhow!("model range offset overflow"))?;
			file.seek(SeekFrom::Start(absolute))?;
			let mut bytes = vec![0_u8; *length];
			file.read_exact(&mut bytes)
				.context("truncated model byte range")?;
			let range_digest = digest_hex(&Sha256::digest(&bytes));
			let end = offset + *length as u64;
			(
				"read_model_artifact",
				json!({"tensor":selected,"file_offset":absolute,
				"offset":offset,"length":length,"next_offset":(end < extent).then_some(end),
				"encoding":"hex","bytes_hex":digest_hex(&bytes),"sha256":range_digest}),
			)
		}
	};
	let after = file.metadata()?;
	#[cfg(unix)]
	super::super::rea_files::ensure_unchanged(&before, &after)?;
	if observed_version != super::observed_version(&after)? {
		bail!("admitted model changed during parsing");
	}
	Ok(json!({
		"record_format":"hepta.rea-model-artifact.v1",
		"rea_evidence_compatible":false,
		"operation":operation,
		"source":{"observed_version":observed_version,"size_bytes":before.len(),
			"header_bytes":directory.header_bytes,"header_sha256":directory.header_sha256},
		"format":directory.format,"format_version":directory.version,
		"byte_order":directory.byte_order,"tensor_data_offset":directory.data_offset,
		"tensor_count":directory.tensors.len(),"metadata_count":directory.metadata.len(),
		"unknown_storage_count":unknown,
		"result":result,
		"coverage":{"header":"complete_within_supported_format","tensor_directory":"complete",
			"tensor_values":"not_interpreted","behavior":"not_evaluated"},
		"limitations":directory.limitations
	}))
}

#[cfg(test)]
#[path = "rea_model_parser_tests.rs"]
mod rea_model_parser_tests;
