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

use super::{ApkInspectionError, ApkResult, StaticLimits, MAX_V1_ENTRIES};
use std::borrow::Cow;
use std::collections::{hash_map::RandomState, BTreeSet};
use std::hash::BuildHasher;

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

fn unsupported(detail: &str, zip64: bool, limits: StaticLimits) -> ApkInspectionError {
	let mut error = ApkInspectionError::unsupported(detail);
	if limits.frozen {
		error.reason = if zip64 {
			format!("This archive uses a Zip64 structure this reader does not decode ({detail}).")
		} else {
			error.remediation_action =
				Some(Box::new("Select a local .apk/.zip/.aab archive.".into()));
			format!("The selected file is not a ZIP/APK ({detail}).")
		}
		.into_boxed_str();
	}
	error
}

fn safe_zip64(bytes: &[u8], at: usize, detail: &str, limits: StaticLimits) -> ApkResult<usize> {
	let n = wide(bytes, at)?;
	if n > SAFE_INTEGER {
		return Err(unsupported(
			if limits.frozen {
				detail
			} else {
				"Zip64 sizes exceed safe range"
			},
			true,
			limits,
		)
		.at(at));
	}
	usize::try_from(n)
		.map_err(|_| unsupported("Zip64 size exceeds addressable range", true, limits).at(at))
}

pub(super) fn zip_tail(bytes: &[u8], limits: StaticLimits) -> ApkResult<ZipTail> {
	if bytes.len() < 22 {
		return Err(unsupported("shorter than a ZIP EOCD record", false, limits));
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
		let detail = if limits.frozen {
			format!("{} end-of-central-directory records each end the archive (one inside another's comment); the central directory is ambiguous", found.len())
		} else {
			"multiple end-of-central-directory records each end the archive; the central directory is ambiguous".into()
		};
		return Err(ApkInspectionError::input(detail).at(found[0]));
	}
	let eocd = found.first().copied().ok_or_else(|| {
		if bytes.starts_with(b"PK\x03\x04") {
			ApkInspectionError::input("ZIP local headers present but no end-of-central-directory (truncated or damaged archive)").at(bytes.len())
		} else { unsupported("no end-of-central-directory record", false, limits) }
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
				return Err(unsupported(
					"multi-disk Zip64 archives are not supported",
					true,
					limits,
				));
			}
			let record = safe_zip64(
				bytes,
				locator + 8,
				"Zip64 EOCD offset exceeds safe range",
				limits,
			)?;
			if record.checked_add(56).is_none_or(|end| end > locator) {
				return Err(ApkInspectionError::input(
					"Zip64 EOCD record extends beyond its locator",
				)
				.at(locator + 8));
			}
			if span(bytes, record, 4)? != b"PK\x06\x06" {
				return Err(ApkInspectionError::input("invalid Zip64 EOCD signature").at(record));
			}
			central = safe_zip64(bytes, record + 48, "Zip64 sizes exceed safe range", limits)?;
			central_size = safe_zip64(bytes, record + 40, "Zip64 sizes exceed safe range", limits)?;
			count = safe_zip64(bytes, record + 32, "Zip64 sizes exceed safe range", limits)?;
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
	if count > limits.zip_entries {
		return Err(ApkInspectionError::capacity(
			"zip-entries",
			limits.zip_entries,
		));
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
	limits: StaticLimits,
) -> ApkResult<Option<SigningBlock<'a>>> {
	let end = tail.central;
	if end < 16 || span(bytes, end - 16, 16)? != b"APK Sig Block 42" {
		return Ok(None);
	}
	if end < 24 {
		// The frozen producer reports cdOffset - 24, which can be negative.
		// Its exact signed byte location is supplied by the caller's block boundary.
		return Err(if limits.frozen {
			ApkInspectionError::input("bad trailing size")
		} else {
			ApkInspectionError::input("bad APK signing-block trailing size").at(end)
		});
	}
	let size = wide(bytes, end - 24)?;
	if !(24..=SAFE_INTEGER).contains(&size) {
		return Err(ApkInspectionError::input(if limits.frozen {
			"bad trailing size"
		} else {
			"bad APK signing-block trailing size"
		})
		.at(end - 24));
	}
	let start = (end as u64).checked_sub(size + 8).ok_or_else(|| {
		ApkInspectionError::input(if limits.frozen {
			"block extends before file start"
		} else {
			"APK signing block extends before file start"
		})
		.at(end)
	})? as usize;
	if wide(bytes, start)? != size {
		return Err(ApkInspectionError::input(if limits.frozen {
			"leading/trailing size mismatch"
		} else {
			"APK signing-block leading/trailing size mismatch"
		})
		.at(start));
	}
	if size + 8 > limits.block_bytes as u64 {
		return Err(ApkInspectionError::capacity(
			"signing-block-bytes",
			limits.block_bytes,
		));
	}
	let mut at = start + 8;
	let pairs_end = end - 24;
	let mut pairs = Vec::new();
	while at < pairs_end {
		if pairs_end - at < 8 {
			return Err(ApkInspectionError::input(if limits.frozen {
				"pair length out of range"
			} else {
				"signing-block pair length out of range"
			})
			.at(at));
		}
		let length = wide(bytes, at)?;
		if length < 4 || length > (pairs_end - at - 8) as u64 {
			return Err(ApkInspectionError::input(if limits.frozen {
				"pair length out of range"
			} else {
				"signing-block pair length out of range"
			})
			.at(at));
		}
		if pairs.len() >= limits.pairs {
			return Err(ApkInspectionError::capacity(
				"signing-block-pairs",
				limits.pairs,
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
	/// Only selected META-INF records need materialized names and local metadata.
	pub entries: Vec<Entry<'a>>,
	pub duplicate_metadata: BTreeSet<Cow<'a, str>>,
	records: usize,
	apksig_records: usize,
	within: DuplicateNames<'a>,
	unread: DuplicateNames<'a>,
}

#[derive(Default)]
struct DuplicateNames<'a> {
	count: usize,
	sample: Vec<NameSample<'a>>,
}

struct NameSample<'a> {
	header: u32,
	name: Cow<'a, str>,
	stored_bytes: usize,
}

#[derive(Clone, Copy)]
struct NameIndex {
	fingerprint: u32,
	header: u32,
}

/// Each offset was checked during the directory walk, before the index is
/// sorted. The immutable input owns all names, so the full index is eight
/// bytes per record instead of one allocated Entry/String per ZIP member.
fn indexed_name(bytes: &[u8], header: u32) -> (&[u8], Cow<'_, str>) {
	let header = header as usize;
	let length = u16::from_le_bytes([bytes[header + 28], bytes[header + 29]]) as usize;
	let raw = &bytes[header + 46..header + 46 + length];
	(raw, java_name(raw))
}

fn add_duplicate<'a>(summary: &mut DuplicateNames<'a>, bytes: &'a [u8], header: u32) {
	summary.count += 1;
	if summary.sample.len() == 5
		&& summary
			.sample
			.last()
			.is_some_and(|entry| entry.header < header)
	{
		return;
	}
	let (raw, name) = indexed_name(bytes, header);
	summary.sample.push(NameSample {
		header,
		name,
		stored_bytes: raw.len(),
	});
	summary.sample.sort_unstable_by_key(|entry| entry.header);
	summary.sample.truncate(5);
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

pub(super) fn directory<'a>(
	bytes: &'a [u8],
	tail: &ZipTail,
	limits: StaticLimits,
) -> ApkResult<Directory<'a>> {
	let end = tail.central + tail.central_size;
	let mut at = tail.central;
	let mut apksig_end = at;
	let mut entries = Vec::new();
	let mut names = Vec::with_capacity(tail.count.min(tail.central_size / 46));
	let hash = RandomState::new();
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
		let header = u32::try_from(at)
			.map_err(|_| ApkInspectionError::capacity("input-bytes", u32::MAX as usize))?;
		names.push(NameIndex {
			fingerprint: hash.hash_one(name.as_ref()) as u32,
			header,
		});
		if raw_name.starts_with(b"META-INF/")
			&& (name == MANIFEST || name.ends_with(".SF") || is_block(&name))
		{
			if entries.len() >= MAX_V1_ENTRIES {
				return Err(ApkInspectionError::capacity(
					"v1-signature-entries",
					MAX_V1_ENTRIES,
				));
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
		}
		at = name_start + name_len + extra + comment;
		if index < tail.classic_count {
			apksig_end = at;
		}
	}
	if at != end {
		let detail = if limits.frozen {
			format!(
				"{} bytes of the declared central directory remain after {} records",
				end as i64 - at as i64,
				tail.count
			)
		} else {
			"central-directory records do not consume the declared extent".into()
		};
		return Err(ApkInspectionError::input(detail).at(at));
	}
	// Hashes only group candidate names. Equality and order within every group
	// use the full Java-decoded name, so a collision never invents a duplicate.
	names.sort_unstable_by(|a, b| {
		a.fingerprint
			.cmp(&b.fingerprint)
			.then_with(|| {
				indexed_name(bytes, a.header)
					.1
					.cmp(&indexed_name(bytes, b.header).1)
			})
			.then(a.header.cmp(&b.header))
	});
	let mut directory = Directory {
		entries,
		duplicate_metadata: BTreeSet::new(),
		records: tail.count,
		apksig_records: tail.classic_count.min(tail.count),
		within: DuplicateNames::default(),
		unread: DuplicateNames::default(),
	};
	let mut at = 0;
	while at < names.len() {
		let first = names[at];
		let (raw_name, name) = indexed_name(bytes, first.header);
		let mut stop = at + 1;
		while stop < names.len()
			&& names[stop].fingerprint == first.fingerprint
			&& indexed_name(bytes, names[stop].header).1 == name
		{
			stop += 1;
		}
		if stop - at > 1 {
			if (names[at + 1].header as usize) < apksig_end {
				add_duplicate(&mut directory.within, bytes, first.header);
			} else {
				add_duplicate(&mut directory.unread, bytes, first.header);
			}
			// The frozen provider conservatively pairs against every selected
			// metadata record, independently of the narrower apksig-read note.
			if raw_name.starts_with(b"META-INF/")
				&& (name == MANIFEST || name.ends_with(".SF") || is_block(&name))
			{
				directory.duplicate_metadata.insert(name);
			}
		}
		at = stop;
	}
	Ok(directory)
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

fn display_name(entry: &NameSample<'_>) -> String {
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
		entry.stored_bytes
	)
}

fn listed(names: &DuplicateNames<'_>) -> String {
	let sample = names
		.sample
		.iter()
		.map(display_name)
		.collect::<Vec<_>>()
		.join(", ");
	if names.count > 5 {
		format!("{sample} and {} more", names.count - 5)
	} else {
		sample
	}
}

fn plural(count: usize) -> String {
	format!("{count} {}", if count == 1 { "name" } else { "names" })
}

pub(super) fn duplicate_note(directory: &Directory<'_>) -> Option<String> {
	let (within, unread) = (&directory.within, &directory.unread);
	if within.count == 0 && unread.count == 0 {
		return None;
	}
	let partial = directory.apksig_records < directory.records;
	let mut note = if partial {
		format!("apksig reads only the first {} of the {} central-directory records (it takes the count from the classic end-of-central-directory record's 16-bit field and ignores the Zip64 count). ", directory.apksig_records, directory.records)
	} else {
		String::new()
	};
	if within.count != 0 {
		note.push_str(&format!("{} central directory holds {} more than once ({}); apksig rejects the v1 signature of an archive with any duplicate entry (\"Duplicate entry\"). A v1 signer whose signature block, .SF or META-INF/MANIFEST.MF name is duplicated carries decode_error; other v1 signers are reported as declared.", if partial { "Among those, the" } else { "The" }, plural(within.count), listed(within)));
	}
	if unread.count != 0 {
		if within.count != 0 {
			note.push(' ');
		}
		note.push_str(&format!(
			"{} ({}) {} duplicated only by records past those, which apksig does not read.",
			plural(unread.count),
			listed(unread),
			if unread.count == 1 { "is" } else { "are" }
		));
	}
	Some(note)
}
