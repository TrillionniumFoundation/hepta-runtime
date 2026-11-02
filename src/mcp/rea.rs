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

//! Native, read-only binary header inspection.
//!
//! This is a deliberately small Rust implementation, not an REA-compatible
//! Evidence producer or a substitute for Ghidra, IDA, Hopper, JADX or Frida.
//! Unknown coverage remains unknown. Remote analysis is not yet supported.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::path::{Path, PathBuf};

use super::runtime::runtime_config;

pub const REA_VERSION: &str = "6.8.0";
pub const REA_SOURCE_COMMIT: &str = "93b8b82db70279e40f484114cff9dc1958dc14ee";
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_TENSOR_HEADER: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
pub struct InspectArtifactParams {
	/// Absolute path of a regular file within a configured controller workspace.
	/// Remote SSH URLs, directories and paths outside workspace roots are refused.
	pub path: String,
}

struct HeaderInfo {
	format: &'static str,
	architecture: Option<&'static str>,
	bits: Option<u8>,
	byte_order: Option<&'static str>,
	facts: Value,
	limitations: Vec<&'static str>,
}

fn sha256_hex(data: &[u8]) -> String {
	let digest = Sha256::digest(data);
	let mut result = String::with_capacity(64);
	for byte in digest {
		let _ = write!(result, "{byte:02x}");
	}
	result
}

fn slice_at(data: &[u8], start: usize, length: usize) -> Result<&[u8]> {
	let end = start
		.checked_add(length)
		.ok_or_else(|| anyhow!("header offset overflow"))?;
	data.get(start..end)
		.ok_or_else(|| anyhow!("truncated artifact header at byte {start}"))
}

fn read_u16(data: &[u8], start: usize, little: bool) -> Result<u16> {
	let a = slice_at(data, start, 2)?;
	let value = [a[0], a[1]];
	Ok(if little {
		u16::from_le_bytes(value)
	} else {
		u16::from_be_bytes(value)
	})
}

fn read_u32(data: &[u8], start: usize, little: bool) -> Result<u32> {
	let a: [u8; 4] = slice_at(data, start, 4)?.try_into()?;
	Ok(if little {
		u32::from_le_bytes(a)
	} else {
		u32::from_be_bytes(a)
	})
}

fn read_u64(data: &[u8], start: usize, little: bool) -> Result<u64> {
	let a: [u8; 8] = slice_at(data, start, 8)?.try_into()?;
	Ok(if little {
		u64::from_le_bytes(a)
	} else {
		u64::from_be_bytes(a)
	})
}

fn elf_machine(machine: u16) -> Option<&'static str> {
	match machine {
		3 => Some("x86"),
		8 => Some("mips"),
		20 => Some("powerpc"),
		40 => Some("arm"),
		62 => Some("x86_64"),
		183 => Some("aarch64"),
		243 => Some("riscv"),
		_ => None,
	}
}

fn pe_machine(machine: u16) -> Option<&'static str> {
	match machine {
		0x014c => Some("x86"),
		0x8664 => Some("x86_64"),
		0x01c0 | 0x01c4 => Some("arm"),
		0xaa64 => Some("aarch64"),
		0x5032 | 0x5064 => Some("riscv"),
		_ => None,
	}
}

fn parse_elf(data: &[u8]) -> Result<HeaderInfo> {
	slice_at(data, 0, 16)?;
	if data[6] != 1 {
		bail!("unsupported ELF identification version");
	}
	let (bits, header_size, entry_offset, shnum_offset) = match data[4] {
		1 => (32, 52, 24, 48),
		2 => (64, 64, 24, 60),
		_ => bail!("unsupported ELF class"),
	};
	let little = match data[5] {
		1 => true,
		2 => false,
		_ => bail!("unsupported ELF byte order"),
	};
	slice_at(data, 0, header_size)?;
	if read_u32(data, 20, little)? != 1 {
		bail!("unsupported ELF header version");
	}
	let machine = read_u16(data, 18, little)?;
	let entry = if bits == 32 {
		u64::from(read_u32(data, entry_offset, little)?)
	} else {
		read_u64(data, entry_offset, little)?
	};
	let declared_sections = read_u16(data, shnum_offset, little)?;
	Ok(HeaderInfo {
		format: "elf",
		architecture: elf_machine(machine),
		bits: Some(bits),
		byte_order: Some(if little { "little" } else { "big" }),
		facts: json!({
			"elf_type": read_u16(data, 16, little)?,
			"machine_id": machine,
			"entry_point": format!("0x{entry:x}"),
			"declared_sections": declared_sections
		}),
		limitations: vec![
			"ELF section, segment, relocation and executable-byte semantics are not validated",
			"A zero declared section count may indicate ELF extended numbering",
		],
	})
}

fn parse_pe(data: &[u8]) -> Result<HeaderInfo> {
	slice_at(data, 0, 64)?;
	let pe_offset = usize::try_from(read_u32(data, 0x3c, true)?)?;
	let signature = slice_at(data, pe_offset, 24)?;
	if &signature[..4] != b"PE\0\0" {
		bail!("invalid PE signature");
	}
	let machine = read_u16(data, pe_offset + 4, true)?;
	let declared_sections = read_u16(data, pe_offset + 6, true)?;
	let optional_size = usize::from(read_u16(data, pe_offset + 20, true)?);
	let optional_start = pe_offset
		.checked_add(24)
		.ok_or_else(|| anyhow!("PE offset overflow"))?;
	slice_at(data, optional_start, optional_size)?;
	let magic = if optional_size >= 2 {
		Some(read_u16(data, optional_start, true)?)
	} else {
		None
	};
	let bits = match magic {
		Some(0x10b) => Some(32),
		Some(0x20b) => Some(64),
		_ => None,
	};
	Ok(HeaderInfo {
        format: "pe",
        architecture: pe_machine(machine),
        bits,
        byte_order: Some("little"),
        facts: json!({
            "machine_id": machine,
            "declared_sections": declared_sections,
            "optional_header_magic": magic
        }),
        limitations: vec![
            "PE section bodies, signatures, imports and executable-byte semantics are not validated",
            "An unknown optional-header magic does not establish an executable architecture",
        ],
    })
}

fn parse_macho(data: &[u8]) -> Result<HeaderInfo> {
	let magic = slice_at(data, 0, 4)?;
	if magic == [0xca, 0xfe, 0xba, 0xbe] || magic == [0xbe, 0xba, 0xfe, 0xca] {
		let little = magic[0] == 0xbe;
		return Ok(HeaderInfo {
			format: "macho-fat",
			architecture: None,
			bits: None,
			byte_order: Some(if little { "little" } else { "big" }),
			facts: json!({"declared_slices": read_u32(data, 4, little)?}),
			limitations: vec![
				"Fat Mach-O slice table and each contained architecture are not validated",
			],
		});
	}
	let (bits, little) = match magic {
		[0xfe, 0xed, 0xfa, 0xce] => (32, false),
		[0xce, 0xfa, 0xed, 0xfe] => (32, true),
		[0xfe, 0xed, 0xfa, 0xcf] => (64, false),
		[0xcf, 0xfa, 0xed, 0xfe] => (64, true),
		_ => bail!("unsupported Mach-O magic"),
	};
	slice_at(data, 0, if bits == 32 { 28 } else { 32 })?;
	let cpu = read_u32(data, 4, little)?;
	let arch = match cpu {
		7 => Some("x86"),
		0x0100_0007 => Some("x86_64"),
		12 => Some("arm"),
		0x0100_000c => Some("aarch64"),
		_ => None,
	};
	Ok(HeaderInfo {
		format: "macho",
		architecture: arch,
		bits: Some(bits),
		byte_order: Some(if little { "little" } else { "big" }),
		facts: json!({
			"cpu_type": cpu,
			"file_type": read_u32(data, 12, little)?,
			"declared_load_commands": read_u32(data, 16, little)?,
			"declared_command_bytes": read_u32(data, 20, little)?
		}),
		limitations: vec![
			"Mach-O load commands, code signatures and executable-byte semantics are not validated",
		],
	})
}

// The dtype table below follows REA 6.8.0's MIT-licensed mapping.
// See LICENSES/REA-MIT.txt for its copyright/license notice.
/// Subset of REA 6.8.0's known safetensors bit-width table.
/// Unknown dtypes are retained as unknown, not rejected as absent.
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

/// Check the shape and file-relative storage ranges for supported tensor types.
/// JSON duplicate-key detection and full model semantics remain unverified.
fn parse_safetensors(data: &[u8], header_bytes: u64) -> Result<HeaderInfo> {
	let size = usize::try_from(header_bytes)?;
	let data_offset = 8usize
		.checked_add(size)
		.ok_or_else(|| anyhow!("header offset overflow"))?;
	let document = slice_at(data, 8, size)?;
	let parsed: Value = super::rea_evidence::parse_unique_json(document)
		.context("invalid safetensors JSON header")?;
	let entries = parsed
		.as_object()
		.ok_or_else(|| anyhow!("safetensors header is not an object"))?;
	let payload_bytes = u64::try_from(data.len() - data_offset)?;
	let mut ranges = Vec::<(u64, u64)>::new();
	let mut checked_lengths = 0usize;
	let mut unknown_types = 0usize;
	for (name, descriptor) in entries {
		if name == "__metadata__" {
			if !descriptor.is_null() {
				let metadata = descriptor
					.as_object()
					.ok_or_else(|| anyhow!("safetensors metadata is not an object"))?;
				if metadata.values().any(|value| !value.is_string()) {
					bail!("safetensors metadata values must be strings");
				}
			}
			continue;
		}
		let item = descriptor
			.as_object()
			.ok_or_else(|| anyhow!("tensor {name} declaration is not an object"))?;
		let dtype = item
			.get("dtype")
			.and_then(Value::as_str)
			.ok_or_else(|| anyhow!("tensor {name} has no string dtype"))?;
		let shape = item
			.get("shape")
			.and_then(Value::as_array)
			.ok_or_else(|| anyhow!("tensor {name} has no shape array"))?;
		let offsets = item
			.get("data_offsets")
			.and_then(Value::as_array)
			.ok_or_else(|| anyhow!("tensor {name} has no data_offsets array"))?;
		if offsets.len() != 2 {
			bail!("tensor {name} must have exactly two data offsets");
		}
		let start = offsets[0]
			.as_u64()
			.ok_or_else(|| anyhow!("tensor {name} has invalid start offset"))?;
		let end = offsets[1]
			.as_u64()
			.ok_or_else(|| anyhow!("tensor {name} has invalid end offset"))?;
		if start > end || end > payload_bytes {
			bail!("tensor {name} range exceeds the file data buffer");
		}
		let mut count = 1u64;
		for dimension in shape {
			let size = dimension
				.as_u64()
				.ok_or_else(|| anyhow!("tensor {name} has invalid shape dimension"))?;
			count = count
				.checked_mul(size)
				.ok_or_else(|| anyhow!("tensor {name} shape product overflows"))?;
		}
		if let Some(bits) = safetensors_bits(dtype) {
			let expected = count
				.checked_mul(bits)
				.ok_or_else(|| anyhow!("tensor {name} storage overflows"))?;
			if expected % 8 != 0 || expected / 8 != end - start {
				bail!("tensor {name} size does not match dtype and shape");
			}
			checked_lengths += 1;
		} else {
			unknown_types += 1;
		}
		ranges.push((start, end));
	}
	ranges.sort_unstable();
	let mut cursor = 0_u64;
	for (start, end) in &ranges {
		if *start != cursor {
			bail!("safetensors tensor data contains a gap or overlap");
		}
		cursor = *end;
	}
	if cursor != payload_bytes {
		bail!("safetensors has unindexed trailing tensor data");
	}
	let mut limitations = vec!["Tensor byte contents and full model semantics are not validated"];
	if unknown_types > 0 {
		limitations.push("Unknown tensor types prevent storage-length verification");
	}
	Ok(HeaderInfo {
		format: "safetensors",
		architecture: None,
		bits: None,
		byte_order: Some("little"),
		facts: json!({
			"header_bytes": header_bytes,
			"declared_tensors": ranges.len(),
			"validated_tensor_ranges": ranges.len(),
			"validated_storage_lengths": checked_lengths,
			"unknown_dtype_tensors": unknown_types
		}),
		limitations,
	})
}

fn parse(data: &[u8]) -> Result<HeaderInfo> {
	if data.starts_with(b"\x7fELF") {
		return parse_elf(data);
	}
	if data.starts_with(b"MZ") {
		return parse_pe(data);
	}
	if data.starts_with(b"\0asm") {
		let version = read_u32(data, 4, true)?;
		if version != 1 {
			bail!("unsupported WebAssembly binary version {version}");
		}
		return Ok(HeaderInfo {
			format: "wasm",
			architecture: Some("wasm"),
			bits: None,
			byte_order: Some("little"),
			facts: json!({"binary_version": version}),
			limitations: vec![
				"WebAssembly sections, code validation and imports are not inspected",
			],
		});
	}
	if data.starts_with(b"GGUF") {
		slice_at(data, 0, 24)?;
		return Ok(HeaderInfo {
			format: "gguf",
			architecture: None,
			bits: None,
			byte_order: Some("little"),
			facts: json!({
				"version": read_u32(data, 4, true)?,
				"declared_tensors": read_u64(data, 8, true)?,
				"declared_metadata_pairs": read_u64(data, 16, true)?
			}),
			limitations: vec![
				"GGUF tensor headers, metadata fields and tensor data are not validated",
			],
		});
	}
	if data.len() >= 9 {
		let length = read_u64(data, 0, true)?;
		if length > 0 && length <= MAX_TENSOR_HEADER && data.get(8) == Some(&b'{') {
			return parse_safetensors(data, length);
		}
	}
	if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
		return Ok(HeaderInfo {
			format: "zip",
			architecture: None,
			bits: None,
			byte_order: None,
			facts: json!({}),
			limitations: vec![
				"ZIP central directory and content signatures are not validated",
				"APK identity and Android manifest contents are unknown",
			],
		});
	}
	if data.len() >= 4
		&& matches!(
			&data[..4],
			[0xca, 0xfe, 0xba, 0xbe]
				| [0xbe, 0xba, 0xfe, 0xca]
				| [0xfe, 0xed, 0xfa, 0xce]
				| [0xce, 0xfa, 0xed, 0xfe]
				| [0xfe, 0xed, 0xfa, 0xcf]
				| [0xcf, 0xfa, 0xed, 0xfe]
		) {
		return parse_macho(data);
	}
	Ok(HeaderInfo {
		format: "unknown",
		architecture: None,
		bits: None,
		byte_order: None,
		facts: json!({}),
		limitations: vec![
			"Unrecognized format: no absence, safety or compatibility conclusions can be drawn",
		],
	})
}

/// Deterministic native preview with an explicitly NON-REA evidence identity.
/// The selected path is returned but is not hashed into the preview identifier.
pub(crate) fn inspect_bytes(data: &[u8], selected_path: &str) -> Result<Value> {
	let header = parse(data)?;
	let file_digest = sha256_hex(data);
	let normalized = json!({
		"format": header.format,
		"architecture": header.architecture,
		"word_size_bits": header.bits,
		"byte_order": header.byte_order,
		"header_facts": header.facts
	});
	let mut identity_material = format!("hepta.rea.preview.v1\0{file_digest}\0").into_bytes();
	identity_material.extend(serde_json::to_vec(&normalized)?);
	let evidence_id = format!("hepta_rea_preview_v1_{}", sha256_hex(&identity_material));
	Ok(json!({
		"record_format": "hepta.rea.preview.v1",
		"native_evidence_id": evidence_id,
		"rea_evidence_compatible": false,
		"upstream_reference": {"repository": "morluto/rea", "version": REA_VERSION, "source_commit": REA_SOURCE_COMMIT},
		"subject": {
			"local_path": selected_path,
			"sha256": file_digest,
			"size_bytes": data.len()
		},
		"operation": "rea_inspect_artifact",
		"analysis_profile": null,
		"normalized_result": normalized,
		"coverage": {"scope": "selected-file-header", "status": "partial"},
		"limitations": header.limitations
	}))
}

/// Read a root-confined snapshot by descriptor, then inspect the exact captured bytes.
async fn inspect_with_roots(path: &Path, roots: &[PathBuf]) -> Result<Value> {
	let data = super::rea_files::read_bounded(path, roots, MAX_FILE_BYTES).await?;
	inspect_bytes(&data, &path.to_string_lossy())
}

pub async fn inspect_artifact(params: InspectArtifactParams) -> Result<String> {
	let roots = &runtime_config()?.controller_workspace_roots;
	let data = super::rea_files::read_bounded(Path::new(&params.path), roots, MAX_FILE_BYTES).await?;
	#[cfg(test)]
	let report = inspect_bytes(&data, &params.path)?;
	#[cfg(not(test))]
	let report = super::rea_worker::inspect_isolated(data, &params.path).await?;
	Ok(serde_json::to_string(&report)?)
}

#[cfg(test)]
#[path = "rea_tests.rs"]
mod rea_tests;
