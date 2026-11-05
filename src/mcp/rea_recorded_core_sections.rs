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

//! Bounded section-constructor checks from the frozen pyelftools 0.33 profile.
//!
//! PN_XNUM constructs section zero before reading its program count. PT_DYNAMIC
//! constructs sections in order until the first matching dynamic section, before
//! validating the segment's backing range. Constructors read only the captured
//! bytes; they do not resolve paths, decode symbols, or traverse dynamic tags.
//! Hash-table bodies and non-ASCII symbol-error names remain explicit native
//! admission boundaries. A shared work limit bounds repeated section traversals.

use super::super::{bytes_at, u16_at, u32_at, u64_at, CoreFailure};

const STRUCTURAL_PREFIX: &str = "Recorded core failed unchanged upstream structural parsing: ";
const SECTION_FIELDS: [u64; 10] = [4, 4, 8, 8, 8, 8, 4, 4, 8, 8];
const COMPRESSION_FIELDS: [u64; 4] = [4, 4, 8, 8];
const MAX_DIAGNOSTIC_NAME_BYTES: usize = 4096;

pub(super) const MAX_SECTION_CONSTRUCTORS: usize = 262_144;

struct Section<'a> {
	header: &'a [u8],
}

fn structural(message: impl AsRef<str>) -> CoreFailure {
	CoreFailure::format(format!("{STRUCTURAL_PREFIX}{}", message.as_ref()))
}

fn overflow() -> CoreFailure {
	CoreFailure::new(
		"decoder",
		"OverflowError: Python int too large to convert to C ssize_t",
	)
}

fn verify_struct(content: &[u8], offset: u128, fields: &[u64]) -> Result<(), CoreFailure> {
	if offset > i64::MAX as u128 {
		return Err(overflow());
	}
	let available = (content.len() as u128).saturating_sub(offset);
	let mut consumed = 0_u128;
	for size in fields {
		let remaining = available.saturating_sub(consumed);
		if remaining < u128::from(*size) {
			return Err(structural(format!("expected {size}, found {remaining}")));
		}
		consumed += u128::from(*size);
	}
	Ok(())
}

fn section(content: &[u8], index: u64) -> Result<Section<'_>, CoreFailure> {
	let start = u64_at(content, 40)?;
	let size = u16_at(content, 58)?;
	if start > 0 && size < 64 {
		return Err(structural(format!("Too small e_shentsize: {size}")));
	}
	// Python computes an unbounded integer before its explicit EOF check; using
	// u128 here preserves that check even for a malicious u64 offset plus index.
	let offset = u128::from(start) + u128::from(index) * u128::from(size);
	if offset > content.len() as u128 {
		return Err(structural(format!(
			"Reading section {index} at offset {offset} past EOF {}",
			content.len()
		)));
	}
	verify_struct(content, offset, &SECTION_FIELDS)?;
	Ok(Section {
		header: bytes_at(content, offset as u64, 64)?,
	})
}

impl Section<'_> {
	fn validate_constructor(&self, content: &[u8]) -> Result<(), CoreFailure> {
		if u64_at(self.header, 8)? & 0x800 != 0 {
			verify_struct(
				content,
				u128::from(u64_at(self.header, 24)?),
				&COMPRESSION_FIELDS,
			)?;
		}
		Ok(())
	}
}

fn is_section_parse_failure(error: &CoreFailure) -> bool {
	error.reason == "format"
		&& (error
			.message
			.starts_with(&format!("{STRUCTURAL_PREFIX}Reading section "))
			|| error
				.message
				.starts_with(&format!("{STRUCTURAL_PREFIX}expected ")))
}

// pyelftools 0.33 decodes known section types to these enum labels before
// constructors report a wrong link type. Unknown types remain decimal integers.
fn section_type_text(section_type: u32, machine: u16) -> String {
	let label = match section_type {
		0 => "SHT_NULL",
		1 => "SHT_PROGBITS",
		2 => "SHT_SYMTAB",
		3 => "SHT_STRTAB",
		4 => "SHT_RELA",
		5 => "SHT_HASH",
		6 => "SHT_DYNAMIC",
		7 => "SHT_NOTE",
		8 => "SHT_NOBITS",
		9 => "SHT_REL",
		10 => "SHT_SHLIB",
		11 => "SHT_DYNSYM",
		14 => "SHT_INIT_ARRAY",
		15 => "SHT_FINI_ARRAY",
		16 => "SHT_PREINIT_ARRAY",
		17 => "SHT_GROUP",
		18 => "SHT_SYMTAB_SHNDX",
		19 => "SHT_RELR",
		20 => "SHT_NUM",
		0x6000_0000 => "SHT_LOOS",
		0x6fff_fff3 => "SHT_SUNW_LDYNSYM",
		0x6fff_fff5 => "SHT_GNU_ATTRIBUTES",
		0x6fff_fff6 => "SHT_GNU_HASH",
		0x6fff_fff7 => "SHT_GNU_LIBLIST",
		0x6fff_fffc => "SHT_SUNW_syminfo",
		0x6fff_fffd => "SHT_GNU_verdef",
		0x6fff_fffe => "SHT_GNU_verneed",
		0x6fff_ffff => "SHT_GNU_versym",
		0x7000_0001 if machine == 62 => "SHT_AMD64_UNWIND",
		0x7000_0003 if machine == 183 => "SHT_AARCH64_ATTRIBUTES",
		0x8000_0000 => "SHT_LOUSER",
		0xffff_ffff => "SHT_HIUSER",
		_ => return section_type.to_string(),
	};
	label.to_owned()
}

fn name_offset(content: &[u8], current: &Section<'_>) -> Result<u128, CoreFailure> {
	let string_index = u16_at(content, 62)?;
	let string_index = if string_index == 0xffff {
		u64::from(u32_at(section(content, 0)?.header, 40)?)
	} else {
		u64::from(string_index)
	};
	let string_table = section(content, string_index).map_err(|error| {
		if is_section_parse_failure(&error) {
			structural("String Table not found")
		} else {
			error
		}
	})?;
	string_table.validate_constructor(content)?;
	// get_string ignores the declared table size. A missing NUL, an offset at
	// EOF, or an offset beyond EOF produces an empty name. No host path is read.
	let offset =
		u128::from(u64_at(string_table.header, 24)?) + u128::from(u32_at(current.header, 0)?);
	if offset > i64::MAX as u128 {
		return Err(overflow());
	}
	Ok(offset)
}

fn work_limit() -> CoreFailure {
	CoreFailure::new(
		"resource-limit",
		"Native recorded-core section-constructor work limit exceeded.",
	)
}

// A name influences the admitted constructors only in symbol-table diagnostics.
// Avoid scanning or allocating unused names; still check the original seek
// before any type/link validation. Non-ASCII repr depends on Python's Unicode
// table, so that exceptional diagnostic remains outside this native profile.
fn diagnostic_name(content: &[u8], offset: u128) -> Result<String, CoreFailure> {
	let suffix = if offset < content.len() as u128 {
		&content[offset as usize..]
	} else {
		&[]
	};
	let scanned = &suffix[..suffix.len().min(MAX_DIAGNOSTIC_NAME_BYTES + 1)];
	let name = match scanned.iter().position(|&byte| byte == 0) {
		Some(length) if length <= MAX_DIAGNOSTIC_NAME_BYTES => &scanned[..length],
		_ if suffix.len() <= MAX_DIAGNOSTIC_NAME_BYTES => &[],
		_ => return Err(work_limit()),
	};
	if !name.is_ascii() {
		return Err(CoreFailure::new(
			"unsupported-target",
			"Native recorded-core symbol-table diagnostics require an ASCII section name.",
		));
	}
	let quote = if name.contains(&b'\'') && !name.contains(&b'"') {
		b'"'
	} else {
		b'\''
	};
	let mut result = String::new();
	result
		.try_reserve(name.len().saturating_mul(4).saturating_add(2))
		.map_err(|_| CoreFailure::allocation())?;
	result.push(char::from(quote));
	for &byte in name {
		match byte {
			b'\\' => result.push_str("\\\\"),
			b'\t' => result.push_str("\\t"),
			b'\n' => result.push_str("\\n"),
			b'\r' => result.push_str("\\r"),
			value if value == quote => {
				result.push('\\');
				result.push(char::from(value));
			}
			0x20..=0x7e => result.push(char::from(byte)),
			value => {
				const HEX: &[u8; 16] = b"0123456789abcdef";
				result.push_str("\\x");
				result.push(char::from(HEX[usize::from(value >> 4)]));
				result.push(char::from(HEX[usize::from(value & 15)]));
			}
		}
	}
	result.push(char::from(quote));
	Ok(result)
}

fn linked_string_table(
	content: &[u8],
	current: &Section<'_>,
	work_remaining: &mut usize,
) -> Result<(), CoreFailure> {
	let index = u64::from(u32_at(current.header, 40)?);
	let linked = section(content, index)?;
	let linked_type = u32_at(linked.header, 4)?;
	if linked_type != 3 {
		let label = section_type_text(linked_type, u16_at(content, 18)?);
		return Err(structural(format!(
			"SHT_SYMTAB section points at section {index} of type {label}, expected SHT_STRTAB"
		)));
	}
	validate_section(content, &linked, work_remaining)
}

fn linked_symbol_table(
	content: &[u8],
	current: &Section<'_>,
	work_remaining: &mut usize,
) -> Result<(), CoreFailure> {
	let index = u64::from(u32_at(current.header, 40)?);
	let linked = section(content, index)?;
	let linked_type = u32_at(linked.header, 4)?;
	if !matches!(linked_type, 2 | 11) {
		let label = section_type_text(linked_type, u16_at(content, 18)?);
		return Err(structural(format!(
			"Section points at section {index} of type {label}, expected SHT_SYMTAB/SHT_DYNSYM"
		)));
	}
	validate_section(content, &linked, work_remaining)
}

fn validate_section(
	content: &[u8],
	current: &Section<'_>,
	work_remaining: &mut usize,
) -> Result<(), CoreFailure> {
	*work_remaining = work_remaining.checked_sub(1).ok_or_else(work_limit)?;
	let name = name_offset(content, current)?;
	let section_type = u32_at(current.header, 4)?;
	match section_type {
		4 | 9 => {
			current.validate_constructor(content)?;
			let expected = if section_type == 4 { 24 } else { 16 };
			if u64_at(current.header, 56)? != expected {
				let label = if section_type == 4 {
					"SHT_RELA"
				} else {
					"SHT_REL"
				};
				return Err(structural(format!(
					"Expected sh_entsize of {label} section to be {expected}"
				)));
			}
		}
		19 => {
			current.validate_constructor(content)?;
			let entry_size = u64_at(current.header, 56)?;
			if entry_size != 8 {
				return Err(structural(format!(
					"Expected RELR entry size to be 8, got {entry_size}"
				)));
			}
		}
		2 | 11 | 0x6fff_fff3 => {
			// The linked string table is constructed before this Section.
			linked_string_table(content, current, work_remaining)?;
			current.validate_constructor(content)?;
			let entry_size = u64_at(current.header, 56)?;
			if entry_size == 0 {
				let name = diagnostic_name(content, name)?;
				return Err(structural(format!(
					"Expected entry size of section {name} to be > 0"
				)));
			}
			if u64_at(current.header, 32)? % entry_size != 0 {
				let name = diagnostic_name(content, name)?;
				return Err(structural(format!(
					"Expected section size to be a multiple of entry size in section {name}"
				)));
			}
		}
		0x6fff_fffd | 0x6fff_fffe => {
			linked_string_table(content, current, work_remaining)?;
			current.validate_constructor(content)?;
		}
		5 | 0x6fff_fff6 | 0x6fff_fffc | 0x6fff_ffff => {
			linked_symbol_table(content, current, work_remaining)?;
			current.validate_constructor(content)?;
			// An empty ELF hash table performs no payload parse. Nonempty ELF
			// and all GNU hash bodies need their own bounded parser and oracle.
			if section_type == 0x6fff_fff6
				|| (section_type == 5 && u64_at(current.header, 32)? != 0)
			{
				return Err(CoreFailure::new("unsupported-target", format!(
					"Native recorded-core section validation does not implement the hash-table body for sh_type={section_type}.",
				)));
			}
		}
		6 => {
			current.validate_constructor(content)?;
			let linked = section(content, u64::from(u32_at(current.header, 40)?))?;
			let linked_type = u32_at(linked.header, 4)?;
			if !matches!(linked_type, 0 | 3 | 8) {
				let label = section_type_text(linked_type, u16_at(content, 18)?);
				return Err(structural(format!(
					"Unexpected section type {label}, expected ('SHT_STRTAB', 'SHT_NOBITS', 'SHT_NULL')"
				)));
			}
			validate_section(content, &linked, work_remaining)?;
		}
		_ => current.validate_constructor(content)?,
	}
	Ok(())
}

pub(super) fn extended_program_count(
	content: &[u8],
	work_remaining: &mut usize,
) -> Result<u64, CoreFailure> {
	let zero = section(content, 0)?;
	validate_section(content, &zero, work_remaining)?;
	Ok(u64::from(u32_at(zero.header, 44)?))
}

pub(super) fn validate_dynamic_segment(
	content: &[u8],
	segment_offset: u64,
	work_remaining: &mut usize,
) -> Result<(), CoreFailure> {
	if u64_at(content, 40)? == 0 {
		return Ok(());
	}
	let count = match u16_at(content, 60)? {
		0 => u64_at(section(content, 0)?.header, 32)?,
		value => u64::from(value),
	};
	for index in 0..count {
		let current = section(content, index)?;
		validate_section(content, &current, work_remaining)?;
		if u32_at(current.header, 4)? == 6 && u64_at(current.header, 24)? == segment_offset {
			// DynamicSegment requests the matched section's link once more,
			// then stops. Invalid later sections are deliberately not visited.
			let linked = section(content, u64::from(u32_at(current.header, 40)?))?;
			validate_section(content, &linked, work_remaining)?;
			break;
		}
	}
	Ok(())
}
