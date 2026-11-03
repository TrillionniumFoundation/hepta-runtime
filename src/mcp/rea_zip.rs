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

//! Bounded, static-only classic ZIP index checks. This does NOT verify APK
//! signatures or manifest semantics, nor decompress any untrusted payload.
//! ZIP64, multi-volume, self-extracting offsets, and appended overlays are
//! deliberately unsupported; report a refusal rather than a false APK fact.

use anyhow::{anyhow, bail, Result};
use serde_json::json;
use std::collections::HashSet;

use super::{read_u16, read_u32, slice_at, HeaderInfo};

pub(super) fn parse_zip(data: &[u8]) -> Result<HeaderInfo> {
	if data.len() < 22 {
		bail!("truncated ZIP end-of-central-directory");
	}
	let last = data.len() - 22;
	let first = last.saturating_sub(65_535);
	let eocd = (first..=last)
		.rev()
		.find(|&offset| {
			data[offset..].starts_with(b"PK\x05\x06")
				&& offset
					+ 22
					+ usize::from(u16::from_le_bytes([
						data[offset + 20],
						data[offset + 21],
					]))
					== data.len()
		})
		.ok_or_else(|| anyhow!("ZIP terminator missing or appended data unsupported"))?;
	if read_u16(data, eocd + 4, true)? != 0
		|| read_u16(data, eocd + 6, true)? != 0
	{
		bail!("multi-volume ZIP is not supported by native preview");
	}
	let count = usize::from(read_u16(data, eocd + 10, true)?);
	if count != usize::from(read_u16(data, eocd + 8, true)?) {
		bail!("ZIP declared central-directory entry counts disagree");
	}
	let size = read_u32(data, eocd + 12, true)?;
	let offset = read_u32(data, eocd + 16, true)?;
	if count == 65_535 || size == u32::MAX || offset == u32::MAX {
		bail!("ZIP64 requires another qualified parser");
	}
	if count > 4096 {
		bail!("ZIP preview exceeds 4096-member budget");
	}
	let start = usize::try_from(offset)?;
	if start.checked_add(usize::try_from(size)?) != Some(eocd) {
		bail!("ZIP central-directory offset and size do not match EOCD");
	}
	let mut cursor = start;
	let mut names = HashSet::<Vec<u8>>::new();
	let mut payloads = Vec::with_capacity(count);
	let mut encrypted = 0usize;
	let mut manifest = false;
	let mut resources = false;
	let mut dex_count = 0usize;
	let mut legacy_signature_count = 0usize;

	for _ in 0..count {
		if slice_at(data, cursor, 4)? != b"PK\x01\x02" {
			bail!("invalid ZIP central-directory entry signature");
		}
		slice_at(data, cursor, 46)?;
		let flags = read_u16(data, cursor + 8, true)?;
		let method = read_u16(data, cursor + 10, true)?;
		let compressed = usize::try_from(read_u32(data, cursor + 20, true)?)?;
		let uncompressed = read_u32(data, cursor + 24, true)?;
		let name_len = usize::from(read_u16(data, cursor + 28, true)?);
		let extra_len = usize::from(read_u16(data, cursor + 30, true)?);
		let comment_len = usize::from(read_u16(data, cursor + 32, true)?);
		let local_offset = usize::try_from(read_u32(data, cursor + 42, true)?)?;
		if read_u16(data, cursor + 34, true)? != 0
			|| compressed == u32::MAX as usize
			|| uncompressed == u32::MAX
			|| local_offset == u32::MAX as usize
		{
			bail!("ZIP64 or multi-volume member is unsupported");
		}
		let central_len = 46usize
			.checked_add(name_len)
			.and_then(|n| n.checked_add(extra_len))
			.and_then(|n| n.checked_add(comment_len))
			.ok_or_else(|| anyhow!("ZIP central-directory entry length overflow"))?;
		let central_end = cursor
			.checked_add(central_len)
			.ok_or_else(|| anyhow!("ZIP central-directory pointer overflow"))?;
		if central_end > eocd {
			bail!("ZIP central-directory member exceeds directory bounds");
		}
		let name = slice_at(data, cursor + 46, name_len)?;
		if name.is_empty()
			|| name.starts_with(b"/")
			|| name.contains(&0)
			|| name.contains(&b'\\')
			|| name
				.split(|byte| *byte == b'/')
				.any(|component| component == b"..")
		{
			bail!("ambiguous or traversing ZIP member path refused");
		}
		if !names.insert(name.to_vec()) {
			bail!("duplicate ZIP member names refused");
		}

		if slice_at(data, local_offset, 4)? != b"PK\x03\x04" {
			bail!("missing ZIP local header");
		}
		slice_at(data, local_offset, 30)?;
		if read_u16(data, local_offset + 6, true)? != flags
			|| read_u16(data, local_offset + 8, true)? != method
		{
			bail!("ZIP local/central flags or compression differ");
		}
		let local_name_len = usize::from(read_u16(data, local_offset + 26, true)?);
		let local_extra_len = usize::from(read_u16(data, local_offset + 28, true)?);
		if name != slice_at(data, local_offset + 30, local_name_len)? {
			bail!("ZIP local and central member names differ");
		}
		let data_start = local_offset
			.checked_add(30)
			.and_then(|n| n.checked_add(local_name_len))
			.and_then(|n| n.checked_add(local_extra_len))
			.ok_or_else(|| anyhow!("ZIP local payload offset overflow"))?;
		let data_end = data_start
			.checked_add(compressed)
			.ok_or_else(|| anyhow!("ZIP payload size overflow"))?;
		if data_end > start {
			bail!("ZIP local payload overlaps central directory");
		}
		payloads.push((local_offset, data_end));
		if flags & 1 != 0 {
			encrypted += 1;
		}
		if name == b"AndroidManifest.xml" {
			manifest = true;
		}
		if name == b"resources.arsc" {
			resources = true;
		}
		if name.starts_with(b"classes") && name.ends_with(b".dex") {
			dex_count += 1;
		}
		if name.starts_with(b"META-INF/")
			&& (name.ends_with(b".RSA")
				|| name.ends_with(b".DSA")
				|| name.ends_with(b".EC"))
		{
			legacy_signature_count += 1;
		}
		cursor = central_end;
	}
	if cursor != eocd {
		bail!("ZIP central-directory trailing member bytes or count mismatch");
	}
	payloads.sort_unstable();
	let mut previous_end = 0usize;
	for (begin, end) in payloads {
		if begin < previous_end {
			bail!("ZIP local member payload ranges overlap");
		}
		previous_end = end;
	}
	Ok(HeaderInfo {
		format: "zip",
		architecture: None,
		bits: None,
		byte_order: None,
		facts: json!({
			"declared_entries":count,
			"checked_central_and_local_entries":count,
			"encrypted_entries":encrypted,
			"android_manifest_entry_present":manifest,
			"android_resources_entry_present":resources,
			"android_dex_entries":dex_count,
			"legacy_signature_entry_count":legacy_signature_count,
			"apk_structure_hint_only":manifest && (resources || dex_count > 0),
		}),
		limitations: vec![
			"Classic ZIP structural preview only; ZIP64, multi-volume and appended data unsupported",
			"ZIP compression, checksum, data descriptor and uncompressed contents not verified",
			"APK signature, Android manifest/resource semantics and APK identity NOT verified",
		],
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	fn push16(dst: &mut Vec<u8>, value: u16) {
		dst.extend_from_slice(&value.to_le_bytes());
	}
	fn push32(dst: &mut Vec<u8>, value: u32) {
		dst.extend_from_slice(&value.to_le_bytes());
	}

	/// Independent minimal classic ZIP fixture writer (stored data, empty CRC).
	/// The parser intentionally does not claim CRC validation.
	fn classic_zip(entries: &[(&str, &str)]) -> Vec<u8> {
		let mut output = Vec::new();
		let mut directory = Vec::new();
		for (name, contents) in entries {
			let name = name.as_bytes();
			let contents = contents.as_bytes();
			let local_offset = u32::try_from(output.len()).expect("small fixture");
			output.extend_from_slice(b"PK\x03\x04");
			for value in [20, 0, 0, 0, 0] {
				push16(&mut output, value);
			}
			for value in [0, contents.len() as u32, contents.len() as u32] {
				push32(&mut output, value);
			}
			push16(&mut output, name.len() as u16);
			push16(&mut output, 0);
			output.extend_from_slice(name);
			output.extend_from_slice(contents);

			directory.extend_from_slice(b"PK\x01\x02");
			for value in [20, 20, 0, 0, 0, 0] {
				push16(&mut directory, value);
			}
			for value in [0, contents.len() as u32, contents.len() as u32] {
				push32(&mut directory, value);
			}
			for value in [name.len() as u16, 0, 0, 0, 0] {
				push16(&mut directory, value);
			}
			push32(&mut directory, 0);
			push32(&mut directory, local_offset);
			directory.extend_from_slice(name);
		}
		let central_offset = u32::try_from(output.len()).expect("small offset");
		let central_size = u32::try_from(directory.len()).expect("small directory");
		output.extend(directory);
		output.extend_from_slice(b"PK\x05\x06");
		for value in [0, 0, entries.len() as u16, entries.len() as u16] {
			push16(&mut output, value);
		}
		push32(&mut output, central_size);
		push32(&mut output, central_offset);
		push16(&mut output, 0);
		output
	}

	#[test]
	fn classic_zip_reports_apk_hints_without_claiming_signature_validity() {
		let bytes = classic_zip(&[
			("AndroidManifest.xml", "manifest"),
			("classes.dex", "dex"),
			("resources.arsc", "resources"),
			("META-INF/CERT.RSA", "unsigned fixture"),
		]);
		let info = parse_zip(&bytes).expect("valid classic ZIP index");
		assert_eq!(info.format, "zip");
		assert_eq!(info.facts["declared_entries"], 4);
		assert_eq!(info.facts["android_manifest_entry_present"], true);
		assert_eq!(info.facts["android_dex_entries"], 1);
		assert_eq!(info.facts["legacy_signature_entry_count"], 1);
		assert_eq!(info.facts["apk_structure_hint_only"], true);
		assert!(info.limitations.iter().any(|x| x.contains("NOT verified")));
		assert!(parse_zip(&bytes[..bytes.len() - 1]).is_err());
		assert!(parse_zip(&bytes[..4]).is_err());
	}

	#[test]
	fn malformed_classic_zip_duplicates_and_local_name_mismatch_fail_closed() {
		let duplicate = classic_zip(&[("name", "a"), ("name", "b")]);
		assert!(parse_zip(&duplicate).is_err());
		let traversal = classic_zip(&[("dir/../file", "a")]);
		assert!(parse_zip(&traversal).is_err());
		let mut mismatch = classic_zip(&[("name", "payload")]);
		let central = mismatch
			.windows(4)
			.position(|part| part == b"PK\x01\x02")
			.expect("central entry");
		mismatch[central + 46] = b'x';
		assert!(parse_zip(&mismatch).is_err());
		let mut bad_offset = classic_zip(&[("name", "payload")]);
		bad_offset[central + 42..central + 46].copy_from_slice(&u32::MAX.to_le_bytes());
		assert!(parse_zip(&bad_offset).is_err());
		let empty = classic_zip(&[]);
		assert_eq!(parse_zip(&empty).expect("empty ZIP").facts["declared_entries"], 0);
	}
}
