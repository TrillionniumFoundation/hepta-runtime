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
use tokio::io::AsyncReadExt;

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
		if length > 0 && length <= MAX_TENSOR_HEADER {
			let end = 8usize + usize::try_from(length)?;
			if data.get(8) == Some(&b'{') {
				let header = slice_at(data, 8, end - 8)?;
				let parsed: Value =
					serde_json::from_slice(header).context("invalid safetensors JSON header")?;
				let entries = parsed
					.as_object()
					.ok_or_else(|| anyhow!("safetensors header is not an object"))?;
				return Ok(HeaderInfo {
					format: "safetensors",
					architecture: None,
					bits: None,
					byte_order: Some("little"),
					facts: json!({
						"declared_tensors": entries.keys().filter(|key| key.as_str() != "__metadata__").count(),
						"header_bytes": length
					}),
					limitations: vec![
						"Tensor offsets, shapes and actual tensor payloads are not validated",
					],
				});
			}
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
fn inspect_bytes(data: &[u8], selected_path: &str) -> Result<Value> {
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

/// Enforce the configured controller workspace roots before reading bytes.
/// This check rejects ordinary symlink escapes. It is NOT a defense against
/// hostile concurrent rename attacks; adversarial inputs require OS isolation.
async fn inspect_with_roots(path: &Path, roots: &[PathBuf]) -> Result<Value> {
	if !path.is_absolute() {
		bail!("REA native inspection requires an absolute local path");
	}
	if roots.is_empty() {
		bail!("REA inspection denied: no controller workspace roots configured");
	}
	let canonical_path = tokio::fs::canonicalize(path)
		.await
		.with_context(|| format!("cannot resolve inspection path {}", path.display()))?;
	let mut inside = false;
	for root in roots {
		let canonical_root = tokio::fs::canonicalize(root)
			.await
			.with_context(|| format!("invalid configured workspace {}", root.display()))?;
		if canonical_path.starts_with(canonical_root) {
			inside = true;
			break;
		}
	}
	if !inside {
		bail!("REA inspection denied: path is outside controller workspace roots");
	}
	let metadata = tokio::fs::metadata(&canonical_path).await?;
	if !metadata.is_file() {
		bail!("REA inspection requires a regular file");
	}
	if metadata.len() > MAX_FILE_BYTES {
		bail!("REA inspection file exceeds 32 MiB preview limit");
	}
	let file = tokio::fs::File::open(&canonical_path).await?;
	let mut data = Vec::new();
	file.take(MAX_FILE_BYTES + 1).read_to_end(&mut data).await?;
	if data.len() as u64 > MAX_FILE_BYTES {
		bail!("REA inspection file exceeds 32 MiB preview limit");
	}
	inspect_bytes(&data, &path.to_string_lossy())
}

pub async fn inspect_artifact(params: InspectArtifactParams) -> Result<String> {
	let roots = &runtime_config()?.controller_workspace_roots;
	let report = inspect_with_roots(Path::new(&params.path), roots).await?;
	Ok(serde_json::to_string(&report)?)
}

#[cfg(test)]
#[path = "rea_tests.rs"]
mod rea_tests;
