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

//! Extended ELF program counts retain the reference's section-zero checks.
//!
//! Ordinary counts never inspect section tables. PN_XNUM does: pyelftools 0.33
//! obtains `get_section(0)["sh_info"]`, including a string-table lookup and the
//! Section constructor's compression-header read. Noncanonical section zero
//! types with additional symbol/hash/version constructors remain outside this
//! native admission. Their bounded constructor-prefix failures are reproduced
//! in source order; passing a prefix never means the constructor was validated.

use super::super::{bytes_at, u16_at, u32_at, u64_at, CoreFailure};

const STRUCTURAL_PREFIX: &str = "Recorded core failed unchanged upstream structural parsing: ";
const SECTION_FIELDS: [u64; 10] = [4, 4, 8, 8, 8, 8, 4, 4, 8, 8];
const COMPRESSION_FIELDS: [u64; 4] = [4, 4, 8, 8];

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

fn section(content: &[u8], index: u32) -> Result<Section<'_>, CoreFailure> {
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

fn validate_specialized_prefix(
	content: &[u8],
	zero: &Section<'_>,
	section_type: u32,
) -> Result<(), CoreFailure> {
	match section_type {
		4 | 9 => {
			// RelocationSection constructs its base Section first, then checks
			// the fixed ELF64 entry size without reading any relocation entries.
			zero.validate_constructor(content)?;
			let expected = if section_type == 4 { 24 } else { 16 };
			if u64_at(zero.header, 56)? != expected {
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
			zero.validate_constructor(content)?;
			let entry_size = u64_at(zero.header, 56)?;
			if entry_size != 8 {
				return Err(structural(format!(
					"Expected RELR entry size to be 8, got {entry_size}"
				)));
			}
		}
		2 | 11 | 0x6fff_fff3 | 0x6fff_fffd | 0x6fff_fffe => {
			// Symbol and version factories resolve the linked header before
			// constructing this section or its compression header.
			let index = u32_at(zero.header, 40)?;
			let linked = section(content, index)?;
			let linked_type = u32_at(linked.header, 4)?;
			if linked_type != 3 {
				let label = section_type_text(linked_type, u16_at(content, 18)?);
				return Err(structural(format!(
					"SHT_SYMTAB section points at section {index} of type {label}, expected SHT_STRTAB"
				)));
			}
		}
		5 | 0x6fff_fff6 | 0x6fff_fffc | 0x6fff_ffff => {
			let index = u32_at(zero.header, 40)?;
			let linked = section(content, index)?;
			let linked_type = u32_at(linked.header, 4)?;
			if !matches!(linked_type, 2 | 11) {
				let label = section_type_text(linked_type, u16_at(content, 18)?);
				return Err(structural(format!(
					"Section points at section {index} of type {label}, expected SHT_SYMTAB/SHT_DYNSYM"
				)));
			}
		}
		6 => {
			// DynamicSection's base constructor precedes get_section's type
			// validation. Accepted linked types require further constructors.
			zero.validate_constructor(content)?;
			let linked = section(content, u32_at(zero.header, 40)?)?;
			let linked_type = u32_at(linked.header, 4)?;
			if !matches!(linked_type, 0 | 3 | 8) {
				let label = section_type_text(linked_type, u16_at(content, 18)?);
				return Err(structural(format!(
					"Unexpected section type {label}, expected ('SHT_STRTAB', 'SHT_NOBITS', 'SHT_NULL')"
				)));
			}
		}
		_ => {}
	}
	Err(CoreFailure::new("unsupported-target", format!(
		"Native recorded-core extended program numbering does not implement the noncanonical section-zero constructor for sh_type={section_type}.",
	)))
}

pub(super) fn extended_program_count(content: &[u8]) -> Result<u64, CoreFailure> {
	let zero = section(content, 0)?;
	let string_index = u16_at(content, 62)?;
	let string_index = if string_index == 0xffff {
		u32_at(zero.header, 40)?
	} else {
		u32::from(string_index)
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
	let name_offset =
		u128::from(u64_at(string_table.header, 24)?) + u128::from(u32_at(zero.header, 0)?);
	if name_offset > i64::MAX as u128 {
		return Err(overflow());
	}
	let section_type = u32_at(zero.header, 4)?;
	if matches!(
		section_type,
		2 | 4
			| 5 | 6 | 9
			| 11 | 19 | 0x6fff_fff3
			| 0x6fff_fff6
			| 0x6fff_fffc
			| 0x6fff_fffd
			| 0x6fff_fffe
			| 0x6fff_ffff
	) {
		validate_specialized_prefix(content, &zero, section_type)?;
	}
	zero.validate_constructor(content)?;
	Ok(u64::from(u32_at(zero.header, 44)?))
}
