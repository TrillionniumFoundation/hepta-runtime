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

//! Seek-based classic ZIP directory validation. APK/JAR roles describe names;
//! no archive member is decompressed, extracted or executed.

use super::{hex, observed_version, ArchiveFilter, MAX_DIRECTORY_BYTES};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

const MAX_ENTRIES: usize = 50_000;
const MAX_STRUCTURE_READ_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
	pub filter: ArchiveFilter,
	pub offset: usize,
	pub limit: usize,
}

#[derive(Serialize)]
struct Entry {
	name: String,
	name_encoding: &'static str,
	role: &'static str,
	central_header_offset: u64,
	local_header_offset: u64,
	payload_offset: u64,
	compressed_bytes: u64,
	uncompressed_bytes: u64,
	compression_method: u16,
	flags: u16,
	encrypted: bool,
	declared_crc32: String,
	data_descriptor_bytes: usize,
	central_extra_field_ids: Vec<u16>,
	content_verified: bool,
}

struct Reader<'a> {
	file: &'a mut File,
	size: u64,
	read_bytes: u64,
}

impl Reader<'_> {
	fn read(&mut self, offset: u64, length: usize) -> Result<Vec<u8>> {
		if offset > self.size || length as u64 > self.size - offset {
			bail!("archive structure extends beyond admitted file size");
		}
		self.read_bytes = self
			.read_bytes
			.checked_add(length as u64)
			.ok_or_else(|| anyhow!("archive structure read budget overflow"))?;
		if self.read_bytes > MAX_STRUCTURE_READ_BYTES {
			bail!("archive structure exceeds 64 MiB I/O budget");
		}
		self.file.seek(SeekFrom::Start(offset))?;
		let mut bytes = vec![0_u8; length];
		self.file
			.read_exact(&mut bytes)
			.context("truncated archive structure")?;
		Ok(bytes)
	}
	fn hash_range(&mut self, offset: u64, length: u64) -> Result<String> {
		let mut hash = Sha256::new();
		let mut consumed = 0;
		while consumed < length {
			let size = usize::try_from((length - consumed).min(64 * 1024))?;
			hash.update(self.read(offset + consumed, size)?);
			consumed += size as u64;
		}
		Ok(hex(&hash.finalize()))
	}
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
	let pair: [u8; 2] = bytes
		.get(offset..offset.saturating_add(2))
		.ok_or_else(|| anyhow!("truncated ZIP u16"))?
		.try_into()?;
	Ok(u16::from_le_bytes(pair))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
	let word: [u8; 4] = bytes
		.get(offset..offset.saturating_add(4))
		.ok_or_else(|| anyhow!("truncated ZIP u32"))?
		.try_into()?;
	Ok(u32::from_le_bytes(word))
}

fn extra_fields(bytes: &[u8]) -> Result<Vec<u16>> {
	let mut cursor = 0;
	let mut ids = Vec::new();
	while cursor < bytes.len() {
		let id = u16_at(bytes, cursor)?;
		let length = usize::from(u16_at(bytes, cursor + 2)?);
		let end = cursor
			.checked_add(4)
			.and_then(|n| n.checked_add(length))
			.ok_or_else(|| anyhow!("ZIP extra-field length overflow"))?;
		if end > bytes.len() {
			bail!("ZIP extra field extends beyond its declared region");
		}
		if id == 0x0001 {
			bail!("ZIP64 extra fields are explicitly unsupported by this reader");
		}
		if id == 0x7075 {
			bail!("ZIP Unicode-path override fields are not qualified; no filename is guessed");
		}
		ids.push(id);
		cursor = end;
	}
	Ok(ids)
}

fn validate_local_extra(bytes: &[u8], method: u16, flags: u16, payload_offset: u64) -> Result<()> {
	// AAPT2 maps kAlign to ZipWriter::kAlign32: the whole local extra region is
	// 1-3 zero bytes placing stored data on a four-byte boundary, without a TLV.
	// Central extras and every other local region keep the strict TLV grammar.
	let android_align32_padding = method == 0
		&& flags & 0x0041 == 0
		&& (1..=3).contains(&bytes.len())
		&& payload_offset.is_multiple_of(4)
		&& bytes.iter().all(|byte| *byte == 0);
	if android_align32_padding {
		return Ok(());
	}
	extra_fields(bytes).map(|_| ())
}

fn member_name(bytes: &[u8], flags: u16) -> Result<(String, &'static str)> {
	if bytes.is_empty()
		|| bytes.contains(&0)
		|| bytes.contains(&b'\\')
		|| bytes.starts_with(b"/")
		|| bytes
			.split(|byte| *byte == b'/')
			.any(|part| part == b".." || part == b".")
		|| (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
	{
		bail!("ambiguous or traversing ZIP member name is refused");
	}
	let utf8 = flags & (1 << 11) != 0;
	if !utf8 && !bytes.is_ascii() {
		bail!("legacy non-ASCII ZIP filename encoding is unknown");
	}
	Ok((
		String::from_utf8(bytes.to_vec()).context("invalid ZIP UTF-8 filename")?,
		if utf8 { "utf8" } else { "ascii" },
	))
}

fn role(name: &str) -> &'static str {
	if name == "AndroidManifest.xml" || name == "META-INF/MANIFEST.MF" {
		"manifest"
	} else if name
		.strip_prefix("classes")
		.and_then(|rest| rest.strip_suffix(".dex"))
		.is_some_and(|middle| middle.is_empty() || middle.bytes().all(|c| c.is_ascii_digit()))
	{
		"dex"
	} else if name.ends_with(".so") || name.ends_with(".dll") || name.ends_with(".dylib") {
		"native_library"
	} else if name.starts_with("META-INF/")
		&& (name.ends_with(".RSA")
			|| name.ends_with(".DSA")
			|| name.ends_with(".EC")
			|| name.ends_with(".SF"))
	{
		"signature_marker"
	} else if name == "resources.arsc" || name.starts_with("res/") || name.starts_with("assets/") {
		"resource"
	} else if name.ends_with(".class") {
		"java_class"
	} else if name.ends_with('/') {
		"directory"
	} else {
		"other"
	}
}

fn descriptor_length(
	reader: &mut Reader<'_>,
	offset: u64,
	central_start: u64,
	crc: u32,
	compressed: u32,
	uncompressed: u32,
) -> Result<usize> {
	if offset > central_start || central_start - offset < 12 {
		bail!("truncated ZIP data descriptor");
	}
	let bytes = reader.read(offset, usize::try_from((central_start - offset).min(16))?)?;
	let unsigned = u32_at(&bytes, 0)? == crc
		&& u32_at(&bytes, 4)? == compressed
		&& u32_at(&bytes, 8)? == uncompressed;
	let signed = bytes.len() == 16
		&& u32_at(&bytes, 0)? == 0x0807_4b50
		&& u32_at(&bytes, 4)? == crc
		&& u32_at(&bytes, 8)? == compressed
		&& u32_at(&bytes, 12)? == uncompressed;
	match (unsigned, signed) {
		(true, false) => Ok(12),
		(false, true) => Ok(16),
		_ => bail!("ZIP data descriptor is ambiguous or disagrees with central declarations"),
	}
}

struct Layout {
	offset: u64,
	size: u64,
	eocd_offset: u64,
	eocd: Vec<u8>,
	count: usize,
}

fn read_layout(reader: &mut Reader<'_>) -> Result<Layout> {
	let tail_length = usize::try_from(reader.size.min(22 + 65_535))?;
	let tail_offset = reader.size - tail_length as u64;
	let tail = reader.read(tail_offset, tail_length)?;
	let end_index = (0..=tail.len() - 22)
		.rev()
		.find(|offset| {
			tail[*offset..].starts_with(b"PK\x05\x06")
				&& u16_at(&tail, offset + 20)
					.is_ok_and(|length| *offset + 22 + usize::from(length) == tail.len())
		})
		.ok_or_else(|| anyhow!("ZIP EOCD missing or trailing overlay unsupported"))?;
	let eocd = tail[end_index..].to_vec();
	let eocd_offset = tail_offset + end_index as u64;
	if u16_at(&eocd, 4)? != 0 || u16_at(&eocd, 6)? != 0 || u16_at(&eocd, 8)? != u16_at(&eocd, 10)? {
		bail!("multi-volume ZIP or inconsistent volume counts are unsupported");
	}
	let count = usize::from(u16_at(&eocd, 10)?);
	let size = u64::from(u32_at(&eocd, 12)?);
	let offset = u64::from(u32_at(&eocd, 16)?);
	if count == u16::MAX as usize
		|| size == u64::from(u32::MAX)
		|| offset == u64::from(u32::MAX)
		|| (eocd_offset >= 20 && reader.read(eocd_offset - 20, 4)? == b"PK\x06\x07")
	{
		bail!("ZIP64 sentinel or locator requires a separately qualified reader");
	}
	if count > MAX_ENTRIES || size > MAX_DIRECTORY_BYTES {
		bail!("archive exceeds native directory count or byte budget");
	}
	if offset.checked_add(size) != Some(eocd_offset) {
		bail!("ZIP central-directory extent does not terminate at EOCD");
	}
	Ok(Layout {
		offset,
		size,
		eocd_offset,
		eocd,
		count,
	})
}

fn read_entry(reader: &mut Reader<'_>, layout: &Layout, cursor: u64) -> Result<(Entry, u64, u64)> {
	if cursor > layout.eocd_offset || layout.eocd_offset - cursor < 46 {
		bail!("ZIP central entry exceeds directory extent");
	}
	let fixed = reader.read(cursor, 46)?;
	if !fixed.starts_with(b"PK\x01\x02") {
		bail!("invalid ZIP central-directory signature");
	}
	let flags = u16_at(&fixed, 8)?;
	let method = u16_at(&fixed, 10)?;
	let crc = u32_at(&fixed, 16)?;
	let compressed = u32_at(&fixed, 20)?;
	let uncompressed = u32_at(&fixed, 24)?;
	let name_length = usize::from(u16_at(&fixed, 28)?);
	let extra_length = usize::from(u16_at(&fixed, 30)?);
	let comment_length = usize::from(u16_at(&fixed, 32)?);
	let local = u32_at(&fixed, 42)?;
	if u16_at(&fixed, 34)? != 0 || [compressed, uncompressed, local].contains(&u32::MAX) {
		bail!("ZIP64 or multi-volume member is unsupported");
	}
	let variable_length = name_length + extra_length + comment_length;
	let next = cursor + 46 + variable_length as u64;
	if next > layout.eocd_offset {
		bail!("ZIP central variable fields exceed directory extent");
	}
	let variable = reader.read(cursor + 46, variable_length)?;
	let raw_name = &variable[..name_length];
	let (name, name_encoding) = member_name(raw_name, flags)?;
	let central_extra = extra_fields(&variable[name_length..name_length + extra_length])?;
	let local = u64::from(local);
	if local > layout.offset || layout.offset - local < 30 {
		bail!("ZIP local header overlaps central directory");
	}
	let local_fixed = reader.read(local, 30)?;
	if !local_fixed.starts_with(b"PK\x03\x04") {
		bail!("ZIP local header signature missing");
	}
	if u16_at(&local_fixed, 6)? != flags || u16_at(&local_fixed, 8)? != method {
		bail!("ZIP local and central flags or compression disagree");
	}
	let local_name_length = usize::from(u16_at(&local_fixed, 26)?);
	let local_extra_length = usize::from(u16_at(&local_fixed, 28)?);
	let payload_offset = local + 30 + local_name_length as u64 + local_extra_length as u64;
	if payload_offset > layout.offset || u64::from(compressed) > layout.offset - payload_offset {
		bail!("ZIP local payload crosses central-directory boundary");
	}
	let local_variable = reader.read(local + 30, local_name_length + local_extra_length)?;
	if raw_name != &local_variable[..local_name_length] {
		bail!("ZIP local and central member names disagree");
	}
	validate_local_extra(
		&local_variable[local_name_length..],
		method,
		flags,
		payload_offset,
	)?;
	let local_declarations = [
		u32_at(&local_fixed, 14)?,
		u32_at(&local_fixed, 18)?,
		u32_at(&local_fixed, 22)?,
	];
	let descriptor = flags & 8 != 0;
	for (local_value, central_value) in
		local_declarations
			.into_iter()
			.zip([crc, compressed, uncompressed])
	{
		if local_value != central_value && !(descriptor && local_value == 0) {
			bail!("ZIP local and central CRC/size declarations disagree");
		}
	}
	if method == 0 && flags & 1 == 0 && compressed != uncompressed {
		bail!("unencrypted stored ZIP member has inconsistent size declarations");
	}
	let payload_end = payload_offset + u64::from(compressed);
	let descriptor_bytes = if descriptor {
		descriptor_length(
			reader,
			payload_end,
			layout.offset,
			crc,
			compressed,
			uncompressed,
		)?
	} else {
		0
	};
	Ok((
		Entry {
			role: role(&name),
			name,
			name_encoding,
			central_header_offset: cursor,
			local_header_offset: local,
			payload_offset,
			compressed_bytes: u64::from(compressed),
			uncompressed_bytes: u64::from(uncompressed),
			compression_method: method,
			flags,
			encrypted: flags & 1 != 0,
			declared_crc32: format!("{crc:08x}"),
			data_descriptor_bytes: descriptor_bytes,
			central_extra_field_ids: central_extra,
			content_verified: false,
		},
		next,
		payload_end + descriptor_bytes as u64,
	))
}

pub(super) fn inspect_file(file: &mut File, request: &Request) -> Result<Value> {
	if !(1..=256).contains(&request.limit) {
		bail!("archive page limit must be between 1 and 256");
	}
	let before = file.metadata()?;
	if !before.is_file() || before.len() < 22 || before.len() > 9_007_199_254_740_991 {
		bail!("archive must be a regular file with an exact, nontruncated extent");
	}
	let version = observed_version(&before)?;
	let mut reader = Reader {
		file,
		size: before.len(),
		read_bytes: 0,
	};
	let layout = read_layout(&mut reader)?;
	let mut cursor = layout.offset;
	let mut retained = 0_usize;
	let mut names = HashSet::new();
	let mut entries = Vec::new();
	let mut local_ranges = Vec::new();
	for _ in 0..layout.count {
		let (entry, next, local_end) = read_entry(&mut reader, &layout, cursor)?;
		retained = retained
			.checked_add(entry.name.len() * 2 + entry.central_extra_field_ids.len() * 2 + 384)
			.ok_or_else(|| anyhow!("archive index retained budget overflow"))?;
		if retained > MAX_RETAINED_BYTES {
			bail!("archive index exceeds 32 MiB retained representation budget");
		}
		if !names.insert(entry.name.clone()) {
			bail!("duplicate ZIP member name is ambiguous");
		}
		local_ranges.push((entry.local_header_offset, local_end));
		entries.push(entry);
		cursor = next;
	}
	if cursor != layout.eocd_offset {
		bail!("ZIP central-directory count or trailing structure differs from declaration");
	}
	local_ranges.sort_unstable();
	let mut previous_end = 0;
	for (index, (start, end)) in local_ranges.iter().enumerate() {
		if (*start < previous_end) || (index == 0 && *start != 0) {
			bail!("ZIP local ranges overlap or a prefixed/self-extracting archive is unsupported");
		}
		previous_end = *end;
	}
	let directory_sha256 = reader.hash_range(layout.offset, layout.size)?;
	let eocd_sha256 = hex(&Sha256::digest(&layout.eocd));
	let selected: Vec<&Entry> = entries
		.iter()
		.filter(|entry| request.filter.matches(entry.role))
		.collect();
	if request.offset > selected.len() {
		bail!("archive page offset exceeds selected collection size");
	}
	let end = request
		.offset
		.saturating_add(request.limit)
		.min(selected.len());
	let mut hints = Vec::new();
	if entries
		.iter()
		.any(|entry| entry.name == "AndroidManifest.xml")
	{
		hints.push("apk_candidate");
	}
	if entries
		.iter()
		.any(|entry| entry.name == "META-INF/MANIFEST.MF")
	{
		hints.push("jar_candidate");
	}
	let after = reader.file.metadata()?;
	#[cfg(unix)]
	super::super::rea_files::ensure_unchanged(&before, &after)?;
	if observed_version(&after)? != version {
		bail!("archive descriptor changed during inspection");
	}
	Ok(json!({
		"record_format":"hepta.rea-archive-index.v1","rea_evidence_compatible":false,
		"operation":"inspect_archive","format":"zip","application_kind_candidates":hints,
		"source":{"observed_version":version,"size_bytes":before.len(),
			"central_directory_offset":layout.offset,"central_directory_bytes":layout.size,
			"central_directory_sha256":directory_sha256,"eocd_offset":layout.eocd_offset,
			"eocd_bytes":layout.eocd.len(),"eocd_sha256":eocd_sha256},
		"entry_count":entries.len(),"encrypted_entry_count":entries.iter().filter(|entry|entry.encrypted).count(),
		"result":{"filter":request.filter,"offset":request.offset,"limit":request.limit,
			"total":selected.len(),"next_offset":(end < selected.len()).then_some(end),
			"rows":&selected[request.offset..end]},
		"coverage":{"central_directory":"complete_within_supported_classic_zip", "local_header_declarations":"checked",
			"entry_payloads":"not_interpreted_or_decompressed","payload_crc32":"not_verified", "signatures":"not_verified"},
		"limitations":[
			"APK/JAR, manifest, DEX, class and native-library labels are filename observations only; content and application identity are unverified.",
			"CRC values and data descriptors are checked for declaration consistency only, not against decompressed payloads.",
			"ZIP64, multi-volume, prefixed/overlaid archives, legacy non-ASCII names and Unicode-path override fields are unsupported.",
			"Bytes between local records and the central directory, including any APK signing block, are not interpreted. No archive member is extracted or executed."
		]
	}))
}

#[cfg(test)]
#[path = "rea_artifact_zip_parser_tests.rs"]
mod rea_artifact_zip_parser_tests;
