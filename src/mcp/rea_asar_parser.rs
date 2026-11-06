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

//! Bounded Electron ASAR Pickle/header interpretation over one admitted fd.
//! Links and unpacked files are declarations only, never filesystem lookups.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use super::{hex, observed_version, valid_digest, MAX_HEADER_BYTES, MAX_SOURCE_BYTES};

pub(super) const MAX_ENTRIES: usize = 50_000;
pub(super) const MAX_VERIFY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_INTEGRITY_BLOCKS: usize = 200_000;
const MAX_PATH_BYTES: usize = 4096;
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
	Index {
		offset: usize,
		limit: usize,
	},
	Read {
		member: String,
		offset: u64,
		length: usize,
		#[serde(default)]
		require_complete: bool,
	},
}

impl Request {
	pub(super) fn validate(&self) -> Result<()> {
		match self {
			Self::Index { offset, limit } => {
				if !(1..=256).contains(limit) || *offset > MAX_ENTRIES {
					bail!("ASAR index requires limit 1..=256 and offset <=50000");
				}
			}
			Self::Read {
				member,
				offset,
				length,
				require_complete,
			} => {
				validate_path(member)?;
				if !(1..=MAX_SOURCE_BYTES).contains(length) || *offset > MAX_VERIFY_BYTES {
					bail!("ASAR internal member read exceeds its byte bounds");
				}
				if *require_complete && *offset != 0 {
					bail!("complete ASAR source acquisition requires offset zero");
				}
			}
		}
		Ok(())
	}
}

pub(super) fn validate_path(path: &str) -> Result<()> {
	if path.is_empty() || path.len() > MAX_PATH_BYTES {
		bail!("ASAR member path must contain 1..=4096 UTF-8 bytes");
	}
	for component in path.split('/') {
		validate_segment(component)?;
	}
	Ok(())
}

fn validate_segment(segment: &str) -> Result<()> {
	if segment.is_empty()
		|| segment == "."
		|| segment == ".."
		|| segment.contains(['/', '\\', ':'])
		|| segment.chars().any(char::is_control)
	{
		bail!("ASAR member names must be unambiguous relative POSIX path components");
	}
	Ok(())
}

fn fields(value: &Map<String, Value>, allowed: &[&str]) -> Result<()> {
	if value.keys().any(|key| !allowed.contains(&key.as_str())) {
		bail!("ASAR header contains fields outside the qualified entry grammar");
	}
	Ok(())
}

fn integer(value: &Value, label: &str) -> Result<u64> {
	value
		.as_u64()
		.filter(|n| *n <= MAX_SAFE_INTEGER)
		.ok_or_else(|| anyhow!("ASAR {label} must be a nonnegative exact integer <=2^53-1"))
}

fn flag(value: &Map<String, Value>, key: &str) -> Result<bool> {
	value
		.get(key)
		.map(|v| {
			v.as_bool()
				.ok_or_else(|| anyhow!("ASAR {key} must be boolean"))
		})
		.transpose()
		.map(|v| v.unwrap_or(false))
}

fn decimal(value: &Value) -> Result<u64> {
	let text = value
		.as_str()
		.ok_or_else(|| anyhow!("ASAR offset must be a decimal string"))?;
	if text.is_empty()
		|| text.len() > 16
		|| (text.len() > 1 && text.starts_with('0'))
		|| !text.bytes().all(|c| c.is_ascii_digit())
	{
		bail!("ASAR offset must be canonical unsigned decimal digits");
	}
	let offset: u64 = text.parse().context("ASAR offset is out of range")?;
	if offset > MAX_SAFE_INTEGER {
		bail!("ASAR offset exceeds exact 2^53-1 range");
	}
	Ok(offset)
}

struct Integrity {
	hash: String,
	block_size: u64,
	blocks: Vec<String>,
}

fn integrity(value: &Value, size: u64, total_blocks: &mut usize) -> Result<Integrity> {
	let object = value
		.as_object()
		.ok_or_else(|| anyhow!("ASAR integrity must be an object"))?;
	fields(object, &["algorithm", "hash", "blockSize", "blocks"])?;
	if object.get("algorithm").and_then(Value::as_str) != Some("SHA256") {
		bail!("ASAR integrity algorithm is unsupported; only explicit SHA256 is qualified");
	}
	let hash = object
		.get("hash")
		.and_then(Value::as_str)
		.filter(|v| valid_digest(v))
		.ok_or_else(|| anyhow!("invalid ASAR declared integrity hash"))?;
	let block_size = integer(
		object.get("blockSize").unwrap_or(&Value::Null),
		"integrity block size",
	)?;
	if block_size == 0 || block_size > MAX_VERIFY_BYTES {
		bail!("ASAR integrity block size must be between 1 and 64 MiB");
	}
	let blocks = object
		.get("blocks")
		.and_then(Value::as_array)
		.ok_or_else(|| anyhow!("ASAR integrity blocks must be an array"))?;
	let expected = size.div_ceil(block_size).max(1);
	if blocks.len() as u64 != expected || blocks.len() > MAX_INTEGRITY_BLOCKS {
		bail!("ASAR integrity block count disagrees with declared member size or exceeds budget");
	}
	*total_blocks = total_blocks
		.checked_add(blocks.len())
		.ok_or_else(|| anyhow!("ASAR integrity block budget overflow"))?;
	if *total_blocks > MAX_INTEGRITY_BLOCKS {
		bail!("ASAR header exceeds 200000 integrity declarations");
	}
	let blocks = blocks
		.iter()
		.map(|v| {
			v.as_str()
				.filter(|v| valid_digest(v))
				.map(str::to_owned)
				.ok_or_else(|| anyhow!("invalid ASAR declared integrity block hash"))
		})
		.collect::<Result<Vec<_>>>()?;
	Ok(Integrity {
		hash: hash.into(),
		block_size,
		blocks,
	})
}

struct Entry {
	path: String,
	kind: &'static str,
	size: Option<u64>,
	offset: Option<u64>,
	unpacked: bool,
	executable: bool,
	link: Option<String>,
	integrity: Option<Integrity>,
}

impl Entry {
	fn row(&self, data_start: u64) -> Value {
		json!({
			"path":self.path,"kind":self.kind,"size_bytes":self.size,
			"relative_data_offset":self.offset,"payload_offset":self.offset.map(|n|data_start+n),
			"unpacked":self.unpacked,"executable_declaration":self.executable,
			"link_target":self.link,"link_followed":false,
			"integrity":self.integrity.as_ref().map(|i|json!({
				"algorithm":"SHA256","declared_hash":i.hash,"block_size":i.block_size,
				"declared_block_count":i.blocks.len(),"content_verified":false
			}))
		})
	}
}

struct Inventory {
	entries: Vec<Entry>,
	blocks: usize,
	data_bytes: u64,
}

impl Inventory {
	fn visit(
		&mut self,
		files: &Map<String, Value>,
		parent: &str,
		depth: usize,
		inherited_unpacked: bool,
	) -> Result<()> {
		if depth > MAX_DEPTH {
			bail!("ASAR directory depth exceeds 32 levels");
		}
		for (name, node) in files {
			validate_segment(name)?;
			let path = if parent.is_empty() {
				name.clone()
			} else {
				format!("{parent}/{name}")
			};
			validate_path(&path)?;
			if self.entries.len() >= MAX_ENTRIES {
				bail!("ASAR header exceeds 50000 entries");
			}
			let node = node
				.as_object()
				.ok_or_else(|| anyhow!("ASAR entry must be an object"))?;
			let unpacked = flag(node, "unpacked")? || inherited_unpacked;
			if let Some(children) = node.get("files") {
				fields(node, &["files", "unpacked"])?;
				let children = children
					.as_object()
					.ok_or_else(|| anyhow!("ASAR directory files must be an object"))?;
				self.entries.push(Entry {
					path: path.clone(),
					kind: "directory",
					size: None,
					offset: None,
					unpacked,
					executable: false,
					link: None,
					integrity: None,
				});
				self.visit(children, &path, depth + 1, unpacked)?;
			} else if let Some(link) = node.get("link") {
				fields(node, &["link", "unpacked"])?;
				let link = link
					.as_str()
					.ok_or_else(|| anyhow!("ASAR link target must be a string"))?;
				validate_path(link)?;
				self.entries.push(Entry {
					path,
					kind: "link",
					size: None,
					offset: None,
					unpacked,
					executable: false,
					link: Some(link.into()),
					integrity: None,
				});
			} else {
				fields(
					node,
					&["size", "offset", "unpacked", "executable", "integrity"],
				)?;
				let size = integer(node.get("size").unwrap_or(&Value::Null), "member size")?;
				let offset = if unpacked {
					if node.contains_key("offset") {
						bail!("unpacked ASAR member cannot declare a packed offset");
					}
					None
				} else {
					let offset = decimal(node.get("offset").unwrap_or(&Value::Null))?;
					if offset > self.data_bytes || size > self.data_bytes - offset {
						bail!("ASAR member data extent exceeds the admitted archive");
					}
					Some(offset)
				};
				let integrity = node
					.get("integrity")
					.map(|v| integrity(v, size, &mut self.blocks))
					.transpose()?;
				self.entries.push(Entry {
					path,
					kind: if unpacked {
						"unpacked_file"
					} else {
						"packed_file"
					},
					size: Some(size),
					offset,
					unpacked,
					executable: flag(node, "executable")?,
					link: None,
					integrity,
				});
			}
		}
		Ok(())
	}

	fn checked_coverage(&mut self) -> Result<u64> {
		let mut spans: Vec<_> = self
			.entries
			.iter()
			.filter_map(|e| match (e.offset, e.size) {
				(Some(start), Some(size)) if size > 0 => Some((start, start + size)),
				_ => None,
			})
			.collect();
		spans.sort_unstable();
		let mut previous_end = 0;
		let mut covered = 0;
		for (start, end) in spans {
			if start < previous_end {
				bail!("ASAR packed member extents overlap");
			}
			covered += end - start;
			previous_end = end;
		}
		self.entries.sort_by(|a, b| a.path.cmp(&b.path));
		Ok(covered)
	}
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
	let word: [u8; 4] = bytes
		.get(offset..offset.saturating_add(4))
		.ok_or_else(|| anyhow!("truncated ASAR Pickle word"))?
		.try_into()?;
	Ok(u32::from_le_bytes(word))
}

fn header(file: &mut File, size: u64) -> Result<(Vec<u8>, u64, Inventory, u64)> {
	file.seek(SeekFrom::Start(0))?;
	let mut prefix = [0u8; 16];
	file.read_exact(&mut prefix)
		.context("truncated ASAR Pickle prefix")?;
	let header_size = u64::from(u32_at(&prefix, 4)?);
	let payload_size = u64::from(u32_at(&prefix, 8)?);
	let json_size = u64::from(u32_at(&prefix, 12)?);
	if u32_at(&prefix, 0)? != 4
		|| !(8..=MAX_HEADER_BYTES).contains(&header_size)
		|| !header_size.is_multiple_of(4)
		|| payload_size != header_size - 4
		|| json_size == 0
		|| json_size > i32::MAX as u64
		|| 4 + json_size.div_ceil(4) * 4 != payload_size
	{
		bail!("unsupported or inconsistent ASAR Pickle lengths");
	}
	let data_start = 8 + header_size;
	if data_start > size {
		bail!("ASAR header extends beyond admitted file");
	}
	let mut bytes = vec![0u8; usize::try_from(data_start)?];
	bytes[..16].copy_from_slice(&prefix);
	file.read_exact(&mut bytes[16..])
		.context("truncated ASAR header")?;
	let json_end = 16 + usize::try_from(json_size)?;
	if bytes[json_end..].iter().any(|v| *v != 0) {
		bail!("nonzero ASAR Pickle padding");
	}
	let raw = &bytes[16..json_end];
	std::str::from_utf8(raw).context("ASAR header must be valid UTF-8")?;
	let value = super::super::rea_evidence::parse_unique_json(raw)?;
	let root = value
		.as_object()
		.ok_or_else(|| anyhow!("ASAR header root must be an object"))?;
	fields(root, &["files"])?;
	let files = root
		.get("files")
		.and_then(Value::as_object)
		.ok_or_else(|| anyhow!("ASAR header requires a files object"))?;
	let mut inventory = Inventory {
		entries: Vec::new(),
		blocks: 0,
		data_bytes: size - data_start,
	};
	inventory.visit(files, "", 0, false)?;
	let covered = inventory.checked_coverage()?;
	Ok((bytes, data_start, inventory, covered))
}

fn read_member(
	file: &mut File,
	entry: &Entry,
	data_start: u64,
	offset: u64,
	length: usize,
	complete: bool,
) -> Result<Value> {
	let (Some(relative), Some(size)) = (entry.offset, entry.size) else {
		bail!("ASAR reads require a packed regular member; directories, links and unpacked files are never followed");
	};
	if size > MAX_VERIFY_BYTES {
		bail!("ASAR selected member exceeds the 64 MiB whole-member verification budget");
	}
	if offset > size {
		bail!("ASAR member byte offset exceeds its size");
	}
	if complete && (offset != 0 || size > length as u64) {
		bail!("ASAR JavaScript source exceeds the complete-source byte budget");
	}
	let take = usize::try_from((size - offset).min(length as u64))?;
	let range_end = offset + take as u64;
	let mut captured = Vec::with_capacity(take);
	let mut full_hash = Sha256::new();
	let mut block_hash = Sha256::new();
	let mut block_filled = 0u64;
	let mut block_index = 0usize;
	let mut consumed = 0u64;
	let mut buffer = [0u8; 64 * 1024];
	file.seek(SeekFrom::Start(data_start + relative))?;
	while consumed < size {
		let block_remaining = entry
			.integrity
			.as_ref()
			.map(|i| i.block_size - block_filled)
			.unwrap_or(u64::MAX);
		let n = usize::try_from(
			(size - consumed)
				.min(buffer.len() as u64)
				.min(block_remaining),
		)?;
		file.read_exact(&mut buffer[..n])
			.context("ASAR selected member changed or ended during verification")?;
		full_hash.update(&buffer[..n]);
		if let Some(integrity) = &entry.integrity {
			block_hash.update(&buffer[..n]);
			block_filled += n as u64;
			if block_filled == integrity.block_size {
				let actual = hex(&block_hash.finalize_reset());
				if integrity.blocks.get(block_index) != Some(&actual) {
					bail!("ASAR selected member integrity block mismatch");
				}
				block_index += 1;
				block_filled = 0;
			}
		}
		let start = consumed.max(offset);
		let end = (consumed + n as u64).min(range_end);
		if start < end {
			captured
				.extend_from_slice(&buffer[(start - consumed) as usize..(end - consumed) as usize]);
		}
		consumed += n as u64;
	}
	let digest = hex(&full_hash.finalize());
	if let Some(integrity) = &entry.integrity {
		if block_filled > 0 || size == 0 {
			let actual = hex(&block_hash.finalize());
			if integrity.blocks.get(block_index) != Some(&actual) {
				bail!("ASAR selected member integrity final block mismatch");
			}
			block_index += 1;
		}
		if block_index != integrity.blocks.len() || digest != integrity.hash {
			bail!("ASAR selected member integrity hash mismatch");
		}
	}
	if captured.len() != take {
		bail!("ASAR captured byte range is incomplete");
	}
	let mut row = entry.row(data_start);
	if entry.integrity.is_some() {
		row["integrity"]["content_verified"] = json!(true);
	}
	Ok(json!({
		"entry":row,"member_sha256":digest,"member_bytes_verified":size,
		"declared_integrity_verified":entry.integrity.is_some(),
		"integrity_status":if entry.integrity.is_some(){"declared_sha256_and_blocks_match"}else{"not_declared"},
		"offset":offset,"length":captured.len(),"next_offset":(range_end<size).then_some(range_end),
		"bytes_hex":hex(&captured),"range_sha256":hex(&Sha256::digest(&captured)),
		"complete_member":offset==0 && range_end==size,"publisher_authenticated":false
	}))
}

pub(super) fn inspect_file(file: &mut File, request: &Request) -> Result<Value> {
	request.validate()?;
	let before = file.metadata()?;
	if !before.is_file() || before.len() < 16 || before.len() > MAX_SAFE_INTEGER {
		bail!("ASAR input must be a regular file of exact, nontruncated extent");
	}
	let version = observed_version(&before)?;
	let (header_bytes, data_start, inventory, covered) = header(file, before.len())?;
	let header_digest = hex(&Sha256::digest(&header_bytes));
	let result = match request {
		Request::Index { offset, limit } => {
			if *offset > inventory.entries.len() {
				bail!("ASAR index offset exceeds entry count");
			}
			let end = (*offset + *limit).min(inventory.entries.len());
			json!({"offset":offset,"limit":limit,"total":inventory.entries.len(),
				"next_offset":(end<inventory.entries.len()).then_some(end),
				"rows":inventory.entries[*offset..end].iter().map(|e|e.row(data_start)).collect::<Vec<_>>()})
		}
		Request::Read {
			member,
			offset,
			length,
			require_complete,
		} => {
			let entry = inventory
				.entries
				.iter()
				.find(|e| e.path == *member)
				.ok_or_else(|| {
					anyhow!("selected ASAR member does not exist in the complete header inventory")
				})?;
			read_member(file, entry, data_start, *offset, *length, *require_complete)?
		}
	};
	#[cfg(unix)]
	super::super::rea_files::ensure_unchanged(&before, &file.metadata()?)?;
	let counts = ["directory", "link", "packed_file", "unpacked_file"]
		.into_iter()
		.map(|kind| {
			(
				kind.to_owned(),
				json!(inventory.entries.iter().filter(|e| e.kind == kind).count()),
			)
		})
		.collect::<Map<_, _>>();
	Ok(json!({
		"record_format":"hepta.rea-asar.v1","rea_evidence_compatible":false,"request":request,
		"source":{"observed_version":version,"size_bytes":before.len(),"header_bytes":data_start,
			"header_sha256":header_digest,"header_sha256_scope":"complete_pickle_header",
			"payload_offset":data_start,"payload_bytes":inventory.data_bytes,
			"referenced_payload_bytes":covered,"unreferenced_payload_bytes":inventory.data_bytes-covered,
			"full_sha256":null,"identity_scope":"pickle_header_and_descriptor_observation"},
		"entry_count":inventory.entries.len(),"entry_counts":counts,"result":result,
		"profile":"electron-asar-canonical-pickle-sha256-v1",
		"target_code_executed":false,"members_extracted":false,"external_files_opened":false,
		"limitations":[
			"The complete header is checked for supported structure, duplicate names and overlapping packed extents. Header identity does not bind unselected payload bytes or an unpacked sidecar tree.",
			"Only explicitly selected packed members are read and hashed. A declared SHA256 and its blocks must match before any selected bytes are returned; other payload integrity remains unverified.",
			"Links and unpacked files are literal declarations and are never followed. Unknown header fields, noncanonical Pickles, ambiguous paths and unsupported integrity algorithms are refused.",
			"Matching self-declared integrity is consistency evidence, not a publisher signature, trusted Electron fuse check, runtime execution proof or REA Evidence identity.",
			"header_sha256 covers archive bytes [0, payload_offset), including both Pickles and padding. Electron fuse checks use the JSON header string alone; their digests are not interchangeable.",
			"Descriptor metadata detects ordinary concurrent modification, not privileged races that restore or defeat those observations. Header and selected byte digests describe the captured data."
		]
	}))
}

#[cfg(test)]
#[path = "rea_asar_parser_tests.rs"]
mod tests;
