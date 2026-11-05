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

//! APK declaration framing. A bad selected v1 local entry stays a local decode
//! error; it must not erase other readable signers. Names follow Java's UTF-8
//! replacement rules, including its single replacement for encoded surrogates.

use super::{ApkInspectionError, ApkResult, MAX_BLOCK, MAX_PAIRS, MAX_V1_ENTRIES};
use std::borrow::Cow;

const MAX_ZIP_ENTRIES: usize = 50_000;
const MANIFEST: &str = "META-INF/MANIFEST.MF";
const SAFE_INTEGER: u64 = (1 << 53) - 1;

pub(super) struct ZipTail {
	pub central: usize,
	pub central_size: usize,
	pub eocd: usize,
	pub count: usize,
	pub classic_count: usize,
}

pub(super) struct SigningBlock<'a> {
	pub start: usize,
	pub pairs: Vec<(u32, &'a [u8])>,
}

pub(super) fn span(bytes: &[u8], at: usize, len: usize) -> ApkResult<&[u8]> {
	bytes
		.get(at..at.saturating_add(len))
		.ok_or_else(|| ApkInspectionError::input("truncated ZIP/APK structure").at(at))
}

pub(super) fn word(bytes: &[u8], at: usize) -> ApkResult<u32> {
	let b = span(bytes, at, 4)?;
	Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub(super) fn short(bytes: &[u8], at: usize) -> ApkResult<u16> {
	let b = span(bytes, at, 2)?;
	Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn wide(bytes: &[u8], at: usize) -> ApkResult<u64> {
	let b = span(bytes, at, 8)?;
	Ok(u64::from_le_bytes([
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
	]))
}

fn safe_zip64(bytes: &[u8], at: usize) -> ApkResult<usize> {
	let n = wide(bytes, at)?;
	if n > SAFE_INTEGER {
		return Err(ApkInspectionError::unsupported("Zip64 sizes exceed safe range").at(at));
	}
	usize::try_from(n)
		.map_err(|_| ApkInspectionError::unsupported("Zip64 size exceeds addressable range").at(at))
}

pub(super) fn zip_tail(bytes: &[u8]) -> ApkResult<ZipTail> {
	if bytes.len() < 22 {
		return Err(ApkInspectionError::unsupported(
			"shorter than a ZIP EOCD record",
		));
	}
	let mut found = Vec::new();
	for at in (bytes.len().saturating_sub(22 + 65535)..=bytes.len() - 22).rev() {
		if &bytes[at..at + 4] == b"PK\x05\x06"
			&& at + 22 + short(bytes, at + 20)? as usize == bytes.len()
		{
			found.push(at);
		}
	}
	if found.len() > 1 {
		return Err(ApkInspectionError::input("multiple end-of-central-directory records each end the archive; the central directory is ambiguous").at(found[0]));
	}
	let eocd = found.first().copied().ok_or_else(|| {
		if bytes.starts_with(b"PK\x03\x04") {
			ApkInspectionError::input("ZIP local headers present but no end-of-central-directory (truncated or damaged archive)").at(bytes.len())
		} else { ApkInspectionError::unsupported("no end-of-central-directory record") }
	})?;
	let classic_count = short(bytes, eocd + 10)? as usize;
	let mut count = classic_count;
	let mut central_size = word(bytes, eocd + 12)? as usize;
	let mut central = word(bytes, eocd + 16)? as usize;
	let mut records_start = eocd;
	if central == u32::MAX as usize
		|| central_size == u32::MAX as usize
		|| count == u16::MAX as usize
	{
		let locator = eocd
			.checked_sub(20)
			.filter(|at| bytes.get(*at..*at + 4) == Some(b"PK\x06\x07"));
		if let Some(locator) = locator {
			let disk = word(bytes, locator + 4)?;
			let disks = word(bytes, locator + 16)?;
			if disks == 0 {
				return Err(
					ApkInspectionError::input("Zip64 locator declares zero disks").at(locator + 16),
				);
			}
			if disk >= disks {
				return Err(ApkInspectionError::input(
					"Zip64 EOCD disk is outside the declared disk count",
				)
				.at(locator + 4));
			}
			if disks > 1 {
				return Err(ApkInspectionError::unsupported(
					"multi-disk Zip64 archives are not supported",
				));
			}
			let record = safe_zip64(bytes, locator + 8)?;
			if record.checked_add(56).is_none_or(|end| end > locator) {
				return Err(ApkInspectionError::input(
					"Zip64 EOCD record extends beyond its locator",
				)
				.at(locator + 8));
			}
			if span(bytes, record, 4)? != b"PK\x06\x06" {
				return Err(ApkInspectionError::input("invalid Zip64 EOCD signature").at(record));
			}
			central = safe_zip64(bytes, record + 48)?;
			central_size = safe_zip64(bytes, record + 40)?;
			count = safe_zip64(bytes, record + 32)?;
			records_start = record;
		} else if central == u32::MAX as usize || central_size == u32::MAX as usize {
			return Err(ApkInspectionError::input("missing Zip64 EOCD locator").at(eocd));
		}
	}
	if central > records_start || central_size > records_start - central {
		return Err(ApkInspectionError::input(
			"central-directory extent overlaps or extends past the ZIP end records",
		)
		.at(eocd));
	}
	if (count == 0 || central_size == 0) && bytes.starts_with(b"PK\x03\x04") {
		return Err(ApkInspectionError::input("end-of-central-directory declares no entries, but the archive holds local file entries").at(eocd));
	}
	if count > MAX_ZIP_ENTRIES {
		return Err(ApkInspectionError::capacity("zip-entries", MAX_ZIP_ENTRIES));
	}
	Ok(ZipTail {
		central,
		central_size,
		eocd,
		count,
		classic_count,
	})
}

pub(super) fn signing_block<'a>(
	bytes: &'a [u8],
	tail: &ZipTail,
) -> ApkResult<Option<SigningBlock<'a>>> {
	let end = tail.central;
	if end < 16 || span(bytes, end - 16, 16)? != b"APK Sig Block 42" {
		return Ok(None);
	}
	if end < 24 {
		return Err(ApkInspectionError::input("bad APK signing-block trailing size").at(end));
	}
	let size = wide(bytes, end - 24)?;
	if !(24..=SAFE_INTEGER).contains(&size) {
		return Err(ApkInspectionError::input("bad APK signing-block trailing size").at(end - 24));
	}
	let start = (end as u64).checked_sub(size + 8).ok_or_else(|| {
		ApkInspectionError::input("APK signing block extends before file start").at(end)
	})? as usize;
	if wide(bytes, start)? != size {
		return Err(
			ApkInspectionError::input("APK signing-block leading/trailing size mismatch").at(start),
		);
	}
	if size + 8 > MAX_BLOCK as u64 {
		return Err(ApkInspectionError::capacity(
			"signing-block-bytes",
			MAX_BLOCK,
		));
	}
	let mut at = start + 8;
	let pairs_end = end - 24;
	let mut pairs = Vec::new();
	while at < pairs_end {
		if pairs_end - at < 8 {
			return Err(ApkInspectionError::input("signing-block pair length out of range").at(at));
		}
		let length = wide(bytes, at)?;
		if length < 4 || length > (pairs_end - at - 8) as u64 {
			return Err(ApkInspectionError::input("signing-block pair length out of range").at(at));
		}
		if pairs.len() >= MAX_PAIRS {
			return Err(ApkInspectionError::capacity(
				"signing-block-pairs",
				MAX_PAIRS,
			));
		}
		pairs.push((
			word(bytes, at + 8)?,
			span(bytes, at + 12, length as usize - 4)?,
		));
		at += 8 + length as usize;
	}
	Ok(Some(SigningBlock { start, pairs }))
}

pub(super) struct Entry<'a> {
	pub name: Cow<'a, str>,
	pub raw_name: &'a [u8],
	pub flags: u16,
	pub method: u16,
	pub crc32: u32,
	pub compressed: u32,
	pub uncompressed: u32,
	pub local: u32,
}

pub(super) struct Directory<'a> {
	pub entries: Vec<Entry<'a>>,
	pub metadata: Vec<usize>,
	pub duplicates: Vec<(usize, usize)>,
}

pub(super) fn is_block(name: &str) -> bool {
	[".RSA", ".DSA", ".EC"]
		.iter()
		.any(|suffix| name.ends_with(suffix))
}

pub(super) fn signature_file(name: &str) -> String {
	match name.rfind('.') {
		Some(at) => format!("{}.SF", &name[..at]),
		None => format!("{name}.SF"),
	}
}

pub(super) fn directory<'a>(bytes: &'a [u8], tail: &ZipTail) -> ApkResult<Directory<'a>> {
	let end = tail.central + tail.central_size;
	let mut at = tail.central;
	let mut entries = Vec::new();
	let mut metadata = Vec::new();
	for index in 0..tail.count {
		if at.checked_add(46).is_none_or(|stop| stop > end) {
			return Err(ApkInspectionError::input(format!(
				"central directory ends after {index} of {} records",
				tail.count
			))
			.at(at));
		}
		if span(bytes, at, 4)? != b"PK\x01\x02" {
			return Err(
				ApkInspectionError::input("central-directory record signature mismatch").at(at),
			);
		}
		let name_len = short(bytes, at + 28)? as usize;
		let extra = short(bytes, at + 30)? as usize;
		let comment = short(bytes, at + 32)? as usize;
		let name_start = at + 46;
		if name_start + name_len > end {
			return Err(ApkInspectionError::input(
				"central-directory file name runs past the directory",
			)
			.at(name_start));
		}
		let raw_name = span(bytes, name_start, name_len)?;
		let name = java_name(raw_name);
		if raw_name.starts_with(b"META-INF/")
			&& (name == MANIFEST || name.ends_with(".SF") || is_block(&name))
		{
			if metadata.len() >= MAX_V1_ENTRIES {
				return Err(ApkInspectionError::capacity(
					"v1-signature-entries",
					MAX_V1_ENTRIES,
				));
			}
			metadata.push(entries.len());
		}
		entries.push(Entry {
			name,
			raw_name,
			flags: short(bytes, at + 8)?,
			method: short(bytes, at + 10)?,
			crc32: word(bytes, at + 16)?,
			compressed: word(bytes, at + 20)?,
			uncompressed: word(bytes, at + 24)?,
			local: word(bytes, at + 42)?,
		});
		at = name_start + name_len + extra + comment;
	}
	if at != end {
		return Err(ApkInspectionError::input(
			"central-directory records do not consume the declared extent",
		)
		.at(at));
	}
	let mut order = (0..entries.len()).collect::<Vec<_>>();
	order.sort_unstable_by(|a, b| entries[*a].name.cmp(&entries[*b].name).then(a.cmp(b)));
	let mut duplicates = Vec::new();
	let mut at = 0;
	while at < order.len() {
		let mut stop = at + 1;
		while stop < order.len() && entries[order[at]].name == entries[order[stop]].name {
			stop += 1;
		}
		if stop - at > 1 {
			duplicates.push((order[at], order[at + 1]));
		}
		at = stop;
	}
	duplicates.sort_unstable_by_key(|pair| pair.0);
	Ok(Directory {
		entries,
		metadata,
		duplicates,
	})
}

fn continuation(b: u8) -> bool {
	b & 0xc0 == 0x80
}

fn name_unit(raw: &[u8], at: usize) -> (usize, bool) {
	let first = raw[at];
	if first < 0x80 {
		return (1, true);
	}
	if !(0xc2..=0xf4).contains(&first) {
		return (1, false);
	}
	let remaining = raw.len() - at;
	let second = raw.get(at + 1).copied().unwrap_or(0);
	let third = raw.get(at + 2).copied().unwrap_or(0);
	if first <= 0xdf {
		return if remaining > 1 && continuation(second) {
			(2, true)
		} else {
			(1, false)
		};
	}
	if first <= 0xef {
		let bad_second = (first == 0xe0 && second & 0xe0 == 0x80) || !continuation(second);
		if remaining > 2 {
			if bad_second {
				return (1, false);
			}
			if !continuation(third) {
				return (2, false);
			}
			return (3, !(first == 0xed && second >= 0xa0));
		}
		return if remaining == 2 && bad_second {
			(1, false)
		} else {
			(remaining, false)
		};
	}
	if remaining == 1 {
		return (1, false);
	}
	let bad_second = (first == 0xf0 && !(0x90..=0xbf).contains(&second))
		|| (first == 0xf4 && second & 0xf0 != 0x80)
		|| !continuation(second);
	if bad_second {
		return (1, false);
	}
	if remaining > 3 {
		if !continuation(third) {
			return (2, false);
		}
		return if continuation(raw[at + 3]) {
			(4, true)
		} else {
			(3, false)
		};
	}
	if remaining == 3 && !continuation(third) {
		(2, false)
	} else {
		(remaining, false)
	}
}

pub(super) fn java_name(raw: &[u8]) -> Cow<'_, str> {
	if let Ok(text) = std::str::from_utf8(raw) {
		return Cow::Borrowed(text);
	}
	let mut text = String::new();
	let mut at = 0;
	while at < raw.len() {
		let (length, valid) = name_unit(raw, at);
		if valid {
			// name_unit recognizes only complete, scalar-value UTF-8 sequences.
			match std::str::from_utf8(&raw[at..at + length]) {
				Ok(unit) => text.push_str(unit),
				Err(_) => text.push('\u{fffd}'),
			}
		} else {
			text.push('\u{fffd}');
		}
		at += length;
	}
	Cow::Owned(text)
}

pub(super) fn local_data<'a>(
	bytes: &'a [u8],
	entry: &Entry<'_>,
	entries_end: usize,
) -> Result<(&'a [u8], bool), String> {
	if [entry.compressed, entry.uncompressed, entry.local].contains(&u32::MAX) {
		return Err("Zip64 entry sizes are not read".into());
	}
	let at = entry.local as usize;
	let end = entries_end.min(bytes.len());
	if at.checked_add(30).is_none_or(|stop| stop > end) {
		return Err(format!("local header at byte {at} is out of range"));
	}
	if bytes.get(at..at + 4) != Some(b"PK\x03\x04") {
		return Err(format!("local header signature mismatch at byte {at}"));
	}
	let read16 = |offset| short(bytes, at + offset).map_err(|e| e.reason.into_string());
	let read32 = |offset| word(bytes, at + offset).map_err(|e| e.reason.into_string());
	let flags = read16(6)?;
	let descriptor = flags & 8 != 0;
	if descriptor != (entry.flags & 8 != 0) {
		return Err(
			"local header and central directory disagree on the data-descriptor flag".into(),
		);
	}
	if !descriptor {
		for (field, offset, expected) in [
			("CRC-32", 14, entry.crc32),
			("compressed size", 18, entry.compressed),
			("uncompressed size", 22, entry.uncompressed),
		] {
			let local = read32(offset)?;
			if local != expected {
				return Err(format!(
					"local header {field} {local} differs from the central directory's {expected}"
				));
			}
		}
	}
	let name_len = read16(26)? as usize;
	let name_start = at + 30;
	if name_start + name_len > end
		|| name_len > entry.raw_name.len()
		|| java_name(&bytes[name_start..name_start + name_len]) != entry.name
	{
		return Err("local header name differs from the central directory's".into());
	}
	let start = name_start + name_len + read16(28)? as usize;
	let stop = start
		.checked_add(entry.compressed as usize)
		.ok_or_else(|| "entry data extent overflows".to_owned())?;
	if stop > end {
		return Err(format!("entry data at byte {start} runs past the entries"));
	}
	Ok((&bytes[start..stop], (entry.flags | flags) & 1 != 0))
}

fn display_name(entry: &Entry<'_>) -> String {
	let name = entry.name.as_ref();
	if name.len() <= 256 {
		return serde_json::Value::String(name.into()).to_string();
	}
	let mut cut = 256;
	while !name.is_char_boundary(cut) {
		cut -= 1;
	}
	format!(
		"{}… ({}-byte name)",
		serde_json::Value::String(name[..cut].into()),
		entry.raw_name.len()
	)
}

fn listed(directory: &Directory<'_>, indices: &[usize]) -> String {
	let sample = indices
		.iter()
		.take(5)
		.map(|index| display_name(&directory.entries[*index]))
		.collect::<Vec<_>>()
		.join(", ");
	if indices.len() > 5 {
		format!("{sample} and {} more", indices.len() - 5)
	} else {
		sample
	}
}

fn plural(count: usize) -> String {
	format!("{count} {}", if count == 1 { "name" } else { "names" })
}

pub(super) fn duplicate_note(directory: &Directory<'_>, classic_count: usize) -> Option<String> {
	let within = directory
		.duplicates
		.iter()
		.filter(|(_, second)| *second < classic_count)
		.map(|(first, _)| *first)
		.collect::<Vec<_>>();
	let unread = directory
		.duplicates
		.iter()
		.filter(|(_, second)| *second >= classic_count)
		.map(|(first, _)| *first)
		.collect::<Vec<_>>();
	if within.is_empty() && unread.is_empty() {
		return None;
	}
	let partial = classic_count < directory.entries.len();
	let mut note = if partial {
		format!("apksig reads only the first {classic_count} of the {} central-directory records (it takes the count from the classic end-of-central-directory record's 16-bit field and ignores the Zip64 count). ", directory.entries.len())
	} else {
		String::new()
	};
	if !within.is_empty() {
		note.push_str(&format!("{} central directory holds {} more than once ({}); apksig rejects the v1 signature of an archive with any duplicate entry (\"Duplicate entry\"). A v1 signer whose signature block, .SF or META-INF/MANIFEST.MF name is duplicated carries decode_error; other v1 signers are reported as declared.", if partial { "Among those, the" } else { "The" }, plural(within.len()), listed(directory, &within)));
	}
	if !unread.is_empty() {
		if !within.is_empty() {
			note.push(' ');
		}
		note.push_str(&format!(
			"{} ({}) {} duplicated only by records past those, which apksig does not read.",
			plural(unread.len()),
			listed(directory, &unread),
			if unread.len() == 1 { "is" } else { "are" }
		));
	}
	Some(note)
}
