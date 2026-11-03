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

//! Bounded ELF table decoding from an already captured immutable byte slice.
//! Offsets are checked before conversion; NOBITS and the extended-numbering
//! null section do not falsely claim file-backed payload ranges.

use anyhow::{anyhow, bail, Result};

const MAX_SECTIONS: u64 = 65_536;
const MAX_PROGRAMS: u64 = 16_384;
pub(super) const MAX_STRING_BYTES: usize = 1024;

pub(super) struct Reader<'a> {
	pub(super) data: &'a [u8],
	pub(super) little: bool,
	pub(super) bits: u8,
}

impl<'a> Reader<'a> {
	pub(super) fn bytes(&self, offset: u64, size: u64) -> Result<&'a [u8]> {
		let end = offset
			.checked_add(size)
			.ok_or_else(|| anyhow!("ELF range overflow"))?;
		let start = usize::try_from(offset)?;
		let end = usize::try_from(end)?;
		self.data
			.get(start..end)
			.ok_or_else(|| anyhow!("ELF range exceeds captured file"))
	}
	pub(super) fn u16(&self, offset: u64) -> Result<u16> {
		let bytes: [u8; 2] = self.bytes(offset, 2)?.try_into()?;
		Ok(if self.little {
			u16::from_le_bytes(bytes)
		} else {
			u16::from_be_bytes(bytes)
		})
	}
	pub(super) fn u32(&self, offset: u64) -> Result<u32> {
		let bytes: [u8; 4] = self.bytes(offset, 4)?.try_into()?;
		Ok(if self.little {
			u32::from_le_bytes(bytes)
		} else {
			u32::from_be_bytes(bytes)
		})
	}
	pub(super) fn u64(&self, offset: u64) -> Result<u64> {
		let bytes: [u8; 8] = self.bytes(offset, 8)?.try_into()?;
		Ok(if self.little {
			u64::from_le_bytes(bytes)
		} else {
			u64::from_be_bytes(bytes)
		})
	}
	fn table(&self, offset: u64, stride: u64, count: u64, expected: u64) -> Result<()> {
		if count == 0 {
			return Ok(());
		}
		if offset == 0 || stride != expected {
			bail!("ELF table offset or entry size is invalid/unsupported");
		}
		let size = stride
			.checked_mul(count)
			.ok_or_else(|| anyhow!("ELF table size overflow"))?;
		self.bytes(offset, size)?;
		Ok(())
	}
}

#[derive(Clone)]
pub(super) struct Section {
	pub(super) name: u32,
	pub(super) kind: u32,
	pub(super) flags: u64,
	pub(super) address: u64,
	pub(super) offset: u64,
	pub(super) size: u64,
	pub(super) link: u32,
	pub(super) info: u32,
	pub(super) alignment: u64,
	pub(super) entry_size: u64,
}

pub(super) struct Program {
	pub(super) kind: u32,
	pub(super) flags: u32,
	pub(super) offset: u64,
	pub(super) virtual_address: u64,
	pub(super) physical_address: u64,
	pub(super) file_size: u64,
	pub(super) memory_size: u64,
	pub(super) alignment: u64,
}

pub(super) struct Elf<'a> {
	pub(super) reader: Reader<'a>,
	pub(super) kind: u16,
	pub(super) machine: u16,
	pub(super) os_abi: u8,
	pub(super) abi_version: u8,
	pub(super) flags: u32,
	pub(super) entry: u64,
	pub(super) sections: Vec<Section>,
	pub(super) programs: Vec<Program>,
	pub(super) names: Option<&'a [u8]>,
	pub(super) extended_sections: bool,
	pub(super) extended_programs: bool,
	pub(super) extended_names: bool,
}

fn section(reader: &Reader<'_>, at: u64) -> Result<Section> {
	Ok(if reader.bits == 64 {
		Section {
			name: reader.u32(at)?,
			kind: reader.u32(at + 4)?,
			flags: reader.u64(at + 8)?,
			address: reader.u64(at + 16)?,
			offset: reader.u64(at + 24)?,
			size: reader.u64(at + 32)?,
			link: reader.u32(at + 40)?,
			info: reader.u32(at + 44)?,
			alignment: reader.u64(at + 48)?,
			entry_size: reader.u64(at + 56)?,
		}
	} else {
		Section {
			name: reader.u32(at)?,
			kind: reader.u32(at + 4)?,
			flags: u64::from(reader.u32(at + 8)?),
			address: u64::from(reader.u32(at + 12)?),
			offset: u64::from(reader.u32(at + 16)?),
			size: u64::from(reader.u32(at + 20)?),
			link: reader.u32(at + 24)?,
			info: reader.u32(at + 28)?,
			alignment: u64::from(reader.u32(at + 32)?),
			entry_size: u64::from(reader.u32(at + 36)?),
		}
	})
}

fn program(reader: &Reader<'_>, at: u64) -> Result<Program> {
	Ok(if reader.bits == 64 {
		Program {
			kind: reader.u32(at)?,
			flags: reader.u32(at + 4)?,
			offset: reader.u64(at + 8)?,
			virtual_address: reader.u64(at + 16)?,
			physical_address: reader.u64(at + 24)?,
			file_size: reader.u64(at + 32)?,
			memory_size: reader.u64(at + 40)?,
			alignment: reader.u64(at + 48)?,
		}
	} else {
		Program {
			kind: reader.u32(at)?,
			offset: u64::from(reader.u32(at + 4)?),
			virtual_address: u64::from(reader.u32(at + 8)?),
			physical_address: u64::from(reader.u32(at + 12)?),
			file_size: u64::from(reader.u32(at + 16)?),
			memory_size: u64::from(reader.u32(at + 20)?),
			flags: reader.u32(at + 24)?,
			alignment: u64::from(reader.u32(at + 28)?),
		}
	})
}

pub(super) fn string_at(table: &[u8], offset: u32) -> Result<&[u8]> {
	if offset == 0 {
		return Ok(&[]);
	}
	let suffix = table
		.get(usize::try_from(offset)?..)
		.ok_or_else(|| anyhow!("ELF string reference exceeds table"))?;
	let end = suffix
		.iter()
		.take(MAX_STRING_BYTES + 1)
		.position(|byte| *byte == 0)
		.ok_or_else(|| {
			anyhow!("ELF string is unterminated or exceeds 1024-byte inspection limit")
		})?;
	Ok(&suffix[..end])
}

pub(super) fn string_table<'a>(reader: &Reader<'a>, table: &Section) -> Result<&'a [u8]> {
	if table.kind != 3 || table.flags & 0x800 != 0 {
		bail!("ELF name table is not an uncompressed STRTAB");
	}
	let bytes = reader.bytes(table.offset, table.size)?;
	if !bytes.is_empty() && (bytes.first() != Some(&0) || bytes.last() != Some(&0)) {
		bail!("ELF string table must begin and end with NUL");
	}
	Ok(bytes)
}

pub(super) fn parse(data: &[u8]) -> Result<Elf<'_>> {
	if data.len() > 32 * 1024 * 1024 {
		bail!("ELF inspection exceeds 32 MiB captured-file limit");
	}
	let ident = data
		.get(..16)
		.ok_or_else(|| anyhow!("truncated ELF identity"))?;
	if &ident[..4] != b"\x7fELF" || ident[6] != 1 {
		bail!("invalid ELF identity or version");
	}
	let bits = match ident[4] {
		1 => 32,
		2 => 64,
		_ => bail!("unsupported ELF class"),
	};
	let little = match ident[5] {
		1 => true,
		2 => false,
		_ => bail!("unsupported ELF byte order"),
	};
	let reader = Reader { data, little, bits };
	let (header_size, ph_size, sh_size, flags_at, sizes_at) = if bits == 64 {
		(64, 56, 64, 48, 52)
	} else {
		(52, 32, 40, 36, 40)
	};
	reader.bytes(0, header_size)?;
	if reader.u32(20)? != 1 || u64::from(reader.u16(sizes_at)?) != header_size {
		bail!("invalid ELF header version or size");
	}
	let (entry, ph_offset, sh_offset) = if bits == 64 {
		(reader.u64(24)?, reader.u64(32)?, reader.u64(40)?)
	} else {
		(
			u64::from(reader.u32(24)?),
			u64::from(reader.u32(28)?),
			u64::from(reader.u32(32)?),
		)
	};
	let ph_stride = u64::from(reader.u16(sizes_at + 2)?);
	let ph_declared = reader.u16(sizes_at + 4)?;
	let sh_stride = u64::from(reader.u16(sizes_at + 6)?);
	let sh_declared = reader.u16(sizes_at + 8)?;
	let name_declared = reader.u16(sizes_at + 10)?;
	let extended_sections = sh_declared == 0 && sh_offset != 0;
	let extended_programs = ph_declared == 0xffff;
	let extended_names = name_declared == 0xffff;
	let first = if sh_offset != 0 {
		reader.table(sh_offset, sh_stride, 1, sh_size)?;
		let first = section(&reader, sh_offset)?;
		if first.kind != 0 {
			bail!("ELF section zero must be SHT_NULL");
		}
		Some(first)
	} else {
		if sh_declared != 0 || name_declared != 0 || extended_programs {
			bail!("ELF section table required by header declarations");
		}
		None
	};
	let sh_count = if extended_sections {
		first
			.as_ref()
			.ok_or_else(|| anyhow!("ELF extended count has no section zero"))?
			.size
	} else {
		u64::from(sh_declared)
	};
	let ph_count = if extended_programs {
		u64::from(
			first
				.as_ref()
				.ok_or_else(|| anyhow!("ELF extended program count has no section zero"))?
				.info,
		)
	} else {
		u64::from(ph_declared)
	};
	let name_index = if extended_names {
		u64::from(
			first
				.as_ref()
				.ok_or_else(|| anyhow!("ELF extended name index has no section zero"))?
				.link,
		)
	} else {
		u64::from(name_declared)
	};
	if sh_count > MAX_SECTIONS || ph_count > MAX_PROGRAMS {
		bail!("ELF table count exceeds bounded inspection capacity");
	}
	if sh_offset != 0 && sh_count == 0 {
		bail!("ELF nonzero section table has zero resolved entries");
	}
	if name_index != 0 && name_index >= sh_count {
		bail!("ELF section-name table index exceeds section count");
	}
	reader.table(sh_offset, sh_stride, sh_count, sh_size)?;
	reader.table(ph_offset, ph_stride, ph_count, ph_size)?;
	let mut sections = Vec::with_capacity(usize::try_from(sh_count)?);
	let mut spans = Vec::new();
	for index in 0..sh_count {
		let current = section(&reader, sh_offset + index * sh_stride)?;
		if current.alignment > 1 && !current.alignment.is_power_of_two() {
			bail!("ELF section alignment is not a power of two");
		}
		if index != 0 && current.kind != 0 && current.kind != 8 {
			reader.bytes(current.offset, current.size)?;
			if current.size > 0 {
				spans.push((current.offset, current.offset + current.size));
			}
		}
		sections.push(current);
	}
	spans.sort_unstable();
	if spans.windows(2).any(|pair| pair[0].1 > pair[1].0) {
		bail!("ELF file-backed section ranges overlap");
	}
	let names = if name_index == 0 {
		None
	} else {
		Some(string_table(
			&reader,
			&sections[usize::try_from(name_index)?],
		)?)
	};
	if let Some(table) = names {
		for current in &sections {
			string_at(table, current.name)?;
		}
	}
	let mut programs = Vec::with_capacity(usize::try_from(ph_count)?);
	for index in 0..ph_count {
		let current = program(&reader, ph_offset + index * ph_stride)?;
		if current.kind != 0 {
			reader.bytes(current.offset, current.file_size)?;
			if current.alignment > 1 && !current.alignment.is_power_of_two() {
				bail!("ELF program alignment is not a power of two");
			}
			if current.kind == 1 {
				if current.file_size > current.memory_size {
					bail!("ELF LOAD file size exceeds memory size");
				}
				current
					.virtual_address
					.checked_add(current.memory_size)
					.ok_or_else(|| anyhow!("ELF LOAD virtual range overflow"))?;
				if current.alignment > 1
					&& current.offset % current.alignment
						!= current.virtual_address % current.alignment
				{
					bail!("ELF LOAD address and file offset have inconsistent alignment");
				}
			}
		}
		programs.push(current);
	}
	Ok(Elf {
		kind: reader.u16(16)?,
		machine: reader.u16(18)?,
		os_abi: ident[7],
		abi_version: ident[8],
		flags: reader.u32(flags_at)?,
		entry,
		reader,
		sections,
		programs,
		names,
		extended_sections,
		extended_programs,
		extended_names,
	})
}
