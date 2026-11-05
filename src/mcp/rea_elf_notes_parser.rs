// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0

//! Complete, bounded ELF note observations over an already admitted stable file snapshot.
//!
//! The caller owns path admission, snapshot identity, cancellation and Evidence retention. This
//! parser follows the frozen REA 6.8.0 note contract independently of the older structure preview.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use serde::Serialize;
use sha2::{Digest, Sha256};

#[path = "rea_elf_notes_compression.rs"]
mod compression;

const MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;
const SHF_COMPRESSED: u64 = 0x800;
const EXAMINATION_LIMITATION: &str = "This workflow does not execute the image, resolve runtime notes, or verify GNU build-id uniqueness against package catalogs.";
const DUPLICATE_LIMITATION: &str = "PT_NOTE and SHT_NOTE are examined independently; the same file range may appear twice when both tables declare it.";
const ABSENT_LIMITATION: &str = "No PT_NOTE program header or SHT_NOTE section was declared. That is not proof the image never carried notes in another container or overlay.";

/// The completed stable snapshot identity, supplied by the owning operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ElfNotesArtifact {
	pub path: String,
	pub sha256: String,
	pub bytes: u64,
}

/// An exact half-open extent in the original image, including any declared note padding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ElfNoteRange {
	pub offset: u64,
	pub bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ElfNoteTableKind {
	Program,
	Section,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ElfNoteTable {
	pub kind: ElfNoteTableKind,
	pub index: u32,
	pub name: Option<String>,
	pub location: ElfNoteRange,
	pub alignment: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ElfNoteDescriptor {
	pub location: ElfNoteRange,
	pub bytes: u32,
	pub sha256: String,
	pub hex: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ElfGnuAbiTag {
	pub os: u32,
	pub os_name: Option<&'static str>,
	pub major: u32,
	pub minor: u32,
	pub subminor: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ElfGnuNote {
	pub build_id_hex: Option<String>,
	pub abi_tag: Option<ElfGnuAbiTag>,
	pub gold_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ElfNoteEntry {
	pub index: u32,
	pub table_kind: ElfNoteTableKind,
	pub table_index: u32,
	pub location: ElfNoteRange,
	pub namesz: u32,
	pub descsz: u32,
	pub r#type: u32,
	pub type_name: &'static str,
	pub owner: String,
	pub owner_bytes_hex: String,
	pub descriptor: ElfNoteDescriptor,
	pub gnu: Option<ElfGnuNote>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ElfNotesCoverage {
	pub status: &'static str,
	pub examined_tables: u32,
	pub examined_entries: u32,
}

/// The complete typed result; no preview rows or clipped target-controlled text are produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ElfNotesReport {
	pub artifact: ElfNotesArtifact,
	pub format: &'static str,
	pub byte_order: &'static str,
	pub machine: u32,
	pub r#type: u32,
	pub type_name: &'static str,
	pub tables: Vec<ElfNoteTable>,
	pub entries: Vec<ElfNoteEntry>,
	pub coverage: ElfNotesCoverage,
	pub limitations: Vec<String>,
}

/// Parser failures retain the resource boundary needed by the public operation's typed errors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ElfNotesFailure {
	Format {
		message: String,
	},
	Unsupported {
		message: String,
	},
	EntryBudget {
		max_entries: u32,
	},
	TextBudget {
		limit_bytes: u64,
	},
	SectionNamesBudget {
		#[serde(serialize_with = "serialize_decimal_u128")]
		minimum_required_bytes: u128,
		max_file_bytes: u64,
	},
}

fn serialize_decimal_u128<S: serde::Serializer>(
	value: &u128,
	serializer: S,
) -> Result<S::Ok, S::Error> {
	serializer.serialize_str(&value.to_string())
}

impl fmt::Display for ElfNotesFailure {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Format { message } | Self::Unsupported { message } => f.write_str(message),
			Self::EntryBudget { max_entries } => {
				write!(f, "ELF note tables exceed the {max_entries}-entry budget.")
			}
			Self::TextBudget { limit_bytes } => {
				write!(f, "ELF note text exceeds the {limit_bytes}-byte budget.")
			}
			Self::SectionNamesBudget { minimum_required_bytes, max_file_bytes } => write!(
				f,
				"ELF source and decoded section names require {minimum_required_bytes} bytes, above the selected max_file_bytes ({max_file_bytes})."
			),
		}
	}
}

impl std::error::Error for ElfNotesFailure {}

fn format_failure(message: impl Into<String>) -> ElfNotesFailure {
	ElfNotesFailure::Format {
		message: message.into(),
	}
}

fn unsupported(message: impl Into<String>) -> ElfNotesFailure {
	ElfNotesFailure::Unsupported {
		message: message.into(),
	}
}

struct Reader<'a> {
	bytes: &'a [u8],
	little: bool,
	wide: bool,
}

impl<'a> Reader<'a> {
	fn slice(&self, offset: u64, length: u64) -> Result<&'a [u8], ElfNotesFailure> {
		let length_in_file = self.bytes.len() as u64;
		if offset > MAX_SAFE_INTEGER
			|| length > MAX_SAFE_INTEGER
			|| length > length_in_file
			|| offset > length_in_file - length
		{
			return Err(format_failure(format!(
				"ELF range {offset} + {length} leaves the artifact."
			)));
		}
		// Both conversions are bounded by this already allocated slice's length.
		Ok(&self.bytes[offset as usize..(offset + length) as usize])
	}

	fn u16(&self, offset: u64) -> Result<u16, ElfNotesFailure> {
		let bytes = self.slice(offset, 2)?;
		Ok(if self.little {
			u16::from_le_bytes([bytes[0], bytes[1]])
		} else {
			u16::from_be_bytes([bytes[0], bytes[1]])
		})
	}

	fn u32(&self, offset: u64) -> Result<u32, ElfNotesFailure> {
		let bytes = self.slice(offset, 4)?;
		Ok(read_u32(bytes, self.little))
	}

	fn word_bits(&self, offset: u64) -> Result<u64, ElfNotesFailure> {
		if !self.wide {
			return Ok(u64::from(self.u32(offset)?));
		}
		let bytes = self.slice(offset, 8)?;
		let word = [
			bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
		];
		Ok(if self.little {
			u64::from_le_bytes(word)
		} else {
			u64::from_be_bytes(word)
		})
	}

	fn word(&self, offset: u64) -> Result<u64, ElfNotesFailure> {
		let value = self.word_bits(offset)?;
		if value > MAX_SAFE_INTEGER {
			return Err(format_failure("ELF offset or size exceeds a safe integer."));
		}
		Ok(value)
	}
}

fn read_u32(bytes: &[u8], little: bool) -> u32 {
	let word = [bytes[0], bytes[1], bytes[2], bytes[3]];
	if little {
		u32::from_le_bytes(word)
	} else {
		u32::from_be_bytes(word)
	}
}

fn fixed_header(bytes: &[u8]) -> Result<(Reader<'_>, u16, u32), ElfNotesFailure> {
	if bytes.len() >= 4 && &bytes[..4] != b"\x7fELF" {
		return Err(format_failure("not an ELF image"));
	}
	if bytes.len() < 16 {
		return Err(format_failure("ELF identification is truncated"));
	}
	let wide = match bytes[4] {
		1 => false,
		2 => true,
		_ => return Err(format_failure("unsupported ELF class")),
	};
	let little = match bytes[5] {
		1 => true,
		2 => false,
		_ => return Err(format_failure("unsupported ELF endianness")),
	};
	if bytes[6] != 1 {
		return Err(format_failure("unsupported ELF identification version"));
	}
	let minimum = if wide { 64 } else { 52 };
	if bytes.len() < minimum {
		return Err(format_failure(format!(
			"truncated ELF header: an ELF{} header needs {minimum} bytes; the file has {}",
			if wide { 64 } else { 32 },
			bytes.len()
		)));
	}
	let reader = Reader {
		bytes,
		little,
		wide,
	};
	let machine = u32::from(reader.u16(18)?);
	if reader.u32(20)? != 1 && !(machine == 190 && bytes[7] == 0x33) {
		return Err(format_failure("unsupported ELF header version"));
	}
	let header_size = reader.u16(if wide { 52 } else { 40 })?;
	if usize::from(header_size) < minimum || usize::from(header_size) > bytes.len() {
		return Err(format_failure("invalid ELF header size"));
	}
	Ok((reader, header_size, machine))
}

#[derive(Clone, Copy)]
enum BudgetField {
	Text,
	Hash,
	Scan,
}

struct TextBudget {
	limit: u64,
	used: u64,
	hashed: u64,
	scanned: u64,
	hashes: HashMap<(u64, u32), String>,
	scans: HashMap<(u64, u32), usize>,
}

impl TextBudget {
	fn new(limit: u64) -> Self {
		Self {
			limit,
			used: 0,
			hashed: 0,
			scanned: 0,
			hashes: HashMap::new(),
			scans: HashMap::new(),
		}
	}

	fn charge(&mut self, bytes: u64, field: BudgetField) -> Result<(), ElfNotesFailure> {
		let current = match field {
			BudgetField::Text => &mut self.used,
			BudgetField::Hash => &mut self.hashed,
			BudgetField::Scan => &mut self.scanned,
		};
		if bytes > self.limit.saturating_sub(*current) {
			return Err(ElfNotesFailure::TextBudget {
				limit_bytes: self.limit,
			});
		}
		*current += bytes;
		Ok(())
	}
}

fn latin1(bytes: &[u8]) -> String {
	bytes.iter().map(|&byte| char::from(byte)).collect()
}

fn hex(bytes: &[u8]) -> String {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut output = String::with_capacity(bytes.len() * 2);
	for &byte in bytes {
		output.push(char::from(DIGITS[usize::from(byte >> 4)]));
		output.push(char::from(DIGITS[usize::from(byte & 15)]));
	}
	output
}

fn add_limitation(limitations: &mut Vec<String>, message: impl Into<String>) {
	let message = message.into();
	if !limitations.contains(&message) {
		limitations.push(message);
	}
}

fn section_name(
	table: &[u8],
	offset: u32,
	text: &mut TextBudget,
	limitations: &mut Vec<String>,
) -> Result<Option<String>, ElfNotesFailure> {
	let offset = u64::from(offset);
	if offset >= table.len() as u64 {
		add_limitation(
			limitations,
			"ELF section names are incomplete because a name offset is outside its string table.",
		);
		return Ok(None);
	}
	let affordable = text.limit - text.used;
	let available = table.len() as u64 - offset;
	let scanned = available.min(affordable + 1);
	let selected = &table[offset as usize..(offset + scanned) as usize];
	let Some(end) = selected.iter().position(|&byte| byte == 0) else {
		text.charge(scanned, BudgetField::Text)?;
		add_limitation(
			limitations,
			"ELF section names are incomplete because a name is not NUL-terminated.",
		);
		return Ok(None);
	};
	text.charge(end as u64, BudgetField::Text)?;
	Ok(Some(latin1(&selected[..end])))
}

struct ParsedNote<'a> {
	location: ElfNoteRange,
	namesz: u32,
	descsz: u32,
	note_type: u32,
	owner: String,
	owner_bytes_hex: String,
	descriptor: &'a [u8],
	descriptor_offset: u64,
}

fn parse_stream<'a>(
	reader: &Reader<'a>,
	offset: u64,
	size: u64,
	alignment: u32,
	max_entries: u32,
	examined: &mut u32,
	text: &mut TextBudget,
) -> Result<Vec<ParsedNote<'a>>, ElfNotesFailure> {
	reader.slice(offset, size)?;
	let mut notes = Vec::new();
	let mut at = 0;
	let alignment = u64::from(alignment);
	while at + 12 <= size {
		*examined += 1;
		if *examined > max_entries {
			return Err(ElfNotesFailure::EntryBudget { max_entries });
		}
		let header = offset + at;
		let namesz = reader.u32(header)?;
		let descsz = reader.u32(header + 4)?;
		let note_type = reader.u32(header + 8)?;
		// Alignment starts at this note's header, not at the table and not at each payload.
		let descriptor_relative = (12 + u64::from(namesz)).div_ceil(alignment) * alignment;
		let next_relative =
			(descriptor_relative + u64::from(descsz)).div_ceil(alignment) * alignment;
		let next = at + next_relative;
		if next > size {
			return Err(format_failure("ELF note entry exceeds its table."));
		}
		if next <= at {
			return Err(format_failure("ELF note alignment did not advance."));
		}
		let name_bytes = reader.slice(header + 12, u64::from(namesz))?;
		let descriptor = reader.slice(header + descriptor_relative, u64::from(descsz))?;
		let owner_end = name_bytes
			.iter()
			.position(|&byte| byte == 0)
			.unwrap_or(name_bytes.len());
		text.charge(owner_end as u64 + u64::from(namesz) * 2, BudgetField::Text)?;
		notes.push(ParsedNote {
			location: ElfNoteRange {
				offset: header,
				bytes: next - at,
			},
			namesz,
			descsz,
			note_type,
			owner: latin1(&name_bytes[..owner_end]),
			owner_bytes_hex: hex(name_bytes),
			descriptor,
			descriptor_offset: header + descriptor_relative,
		});
		at = next;
	}
	if reader
		.slice(offset + at, size - at)?
		.iter()
		.any(|&byte| byte != 0)
	{
		return Err(format_failure(
			"ELF note table has trailing non-zero bytes.",
		));
	}
	Ok(notes)
}

fn gnu_type_name(note_type: u32) -> &'static str {
	match note_type {
		1 => "gnu_abi_tag",
		2 => "gnu_hwcap",
		3 => "gnu_build_id",
		4 => "gnu_gold_version",
		5 => "gnu_property",
		_ => "unknown",
	}
}

fn decode_gnu(
	note: &ParsedNote<'_>,
	little: bool,
	text: &mut TextBudget,
) -> Result<Option<ElfGnuNote>, ElfNotesFailure> {
	if note.owner != "GNU" {
		return Ok(None);
	}
	let mut gnu = ElfGnuNote::default();
	match note.note_type {
		3 if !note.descriptor.is_empty() => {
			text.charge(u64::from(note.descsz) * 2, BudgetField::Text)?;
			gnu.build_id_hex = Some(hex(note.descriptor));
		}
		1 if note.descriptor.len() == 16 => {
			let os = read_u32(note.descriptor, little);
			gnu.abi_tag = Some(ElfGnuAbiTag {
				os,
				os_name: match os {
					0 => Some("linux"),
					1 => Some("hurd"),
					2 => Some("solaris"),
					3 => Some("freebsd"),
					4 => Some("netbsd"),
					5 => Some("syllable"),
					6 => Some("nacl"),
					_ => None,
				},
				major: read_u32(&note.descriptor[4..], little),
				minor: read_u32(&note.descriptor[8..], little),
				subminor: read_u32(&note.descriptor[12..], little),
			});
		}
		4 => {
			let range = (note.descriptor_offset, note.descsz);
			let end = if let Some(&end) = text.scans.get(&range) {
				end
			} else {
				text.charge(u64::from(note.descsz), BudgetField::Scan)?;
				let end = note
					.descriptor
					.iter()
					.rposition(|&byte| byte != 0)
					.map_or(0, |at| at + 1);
				text.scans.insert(range, end);
				end
			};
			text.charge(end as u64, BudgetField::Text)?;
			gnu.gold_version = Some(latin1(&note.descriptor[..end]));
		}
		_ => {}
	}
	Ok(Some(gnu))
}

fn to_entry(
	note: ParsedNote<'_>,
	kind: ElfNoteTableKind,
	table_index: u32,
	index: u32,
	little: bool,
	text: &mut TextBudget,
) -> Result<ElfNoteEntry, ElfNotesFailure> {
	let range = (note.descriptor_offset, note.descsz);
	let digest = if let Some(digest) = text.hashes.get(&range) {
		digest.clone()
	} else {
		text.charge(u64::from(note.descsz), BudgetField::Hash)?;
		let digest = hex(&Sha256::digest(note.descriptor));
		text.hashes.insert(range, digest.clone());
		digest
	};
	let gnu = decode_gnu(&note, little, text)?;
	Ok(ElfNoteEntry {
		index,
		table_kind: kind,
		table_index,
		location: note.location,
		namesz: note.namesz,
		descsz: note.descsz,
		r#type: note.note_type,
		type_name: if note.owner == "GNU" {
			gnu_type_name(note.note_type)
		} else {
			"unknown"
		},
		owner: note.owner,
		owner_bytes_hex: note.owner_bytes_hex,
		descriptor: ElfNoteDescriptor {
			location: ElfNoteRange {
				offset: note.descriptor_offset,
				bytes: u64::from(note.descsz),
			},
			bytes: note.descsz,
			sha256: digest,
			hex: (note.descsz <= 64).then(|| hex(note.descriptor)),
		},
		gnu,
	})
}

/// Parse the admitted image using default-filled, schema-validated limits supplied by the caller.
/// `artifact` must identify `bytes`; the owning service validates the returned identity and ranges.
pub fn parse_elf_notes(
	bytes: &[u8],
	artifact: ElfNotesArtifact,
	max_file_bytes: u64,
	max_entries: u32,
) -> Result<ElfNotesReport, ElfNotesFailure> {
	let (reader, header_size, machine) = fixed_header(bytes)?;
	let wide = reader.wide;
	let object_type = u32::from(reader.u16(16)?);
	let phoff = reader.word(if wide { 32 } else { 28 })?;
	let shoff = reader.word(if wide { 40 } else { 32 })?;
	let phentsize = u64::from(reader.u16(if wide { 54 } else { 42 })?);
	let phnum = u32::from(reader.u16(if wide { 56 } else { 44 })?);
	let shentsize = u64::from(reader.u16(if wide { 58 } else { 46 })?);
	let shnum = u32::from(reader.u16(if wide { 60 } else { 48 })?);
	let shstrndx = u32::from(reader.u16(if wide { 62 } else { 50 })?);
	if phnum == 0xffff || shnum == 0xffff || shstrndx == 0xffff || (shoff != 0 && shnum == 0) {
		return Err(unsupported("ELF extended numbering is unsupported."));
	}
	if phnum != 0 {
		if phentsize < if wide { 56 } else { 32 } {
			return Err(format_failure("ELF program header width is invalid."));
		}
		reader.slice(phoff, u64::from(phnum) * phentsize)?;
	}
	if shnum != 0 {
		if shentsize < if wide { 64 } else { 40 } {
			return Err(format_failure("ELF section header width is invalid."));
		}
		reader.slice(shoff, u64::from(shnum) * shentsize)?;
	}
	let mut text = TextBudget::new((bytes.len() as u64).min(max_file_bytes));
	let mut name_limitations = Vec::new();
	let mut names: Option<Cow<'_, [u8]>> = None;
	if shnum != 0 && shstrndx != 0 {
		if shstrndx >= shnum {
			return Err(format_failure("ELF section name index is out of range."));
		}
		let header = shoff + u64::from(shstrndx) * shentsize;
		if reader.u32(header + 4)? != 3 {
			return Err(format_failure(
				"ELF section name table is not a string table.",
			));
		}
		let offset = reader.word(header + if wide { 24 } else { 16 })?;
		let size = reader.word(header + if wide { 32 } else { 20 })?;
		let raw = reader.slice(offset, size)?;
		let flags = reader.word_bits(header + 8)?;
		if flags & SHF_COMPRESSED == 0 {
			names = Some(Cow::Borrowed(raw));
		} else {
			match compression::decode_names(raw, wide, reader.little, bytes.len() as u64, max_file_bytes)? {
				compression::DecodedNames::Available(decoded) => {
					text.limit = bytes.len() as u64 + decoded.len() as u64;
					names = Some(Cow::Owned(decoded));
				}
				compression::DecodedNames::Unsupported(kind) => add_limitation(&mut name_limitations,
					format!("ELF section names are unavailable because compression type {kind} is unsupported.")),
			}
		}
	} else if shnum != 0 {
		add_limitation(
			&mut name_limitations,
			"ELF section names are unavailable because no section-name string table is declared.",
		);
	}
	let mut tables = Vec::new();
	let mut entries = Vec::new();
	let mut examined = 0;
	if phnum != 0 {
		if phoff < u64::from(header_size) {
			return Err(format_failure(
				"ELF program header table overlaps the native header.",
			));
		}
		for index in 0..phnum {
			let at = phoff + u64::from(index) * phentsize;
			if reader.u32(at)? != 4 {
				continue;
			}
			let offset = reader.word(at + if wide { 8 } else { 4 })?;
			let size = reader.word(at + if wide { 32 } else { 16 })?;
			let declared_alignment = reader.word(at + if wide { 48 } else { 28 })?;
			let alignment = if declared_alignment == 8 { 8 } else { 4 };
			tables.push(ElfNoteTable {
				kind: ElfNoteTableKind::Program,
				index,
				name: None,
				location: ElfNoteRange {
					offset,
					bytes: size,
				},
				alignment,
			});
			// Upstream completes a whole stream before hashing/decoding its descriptors; preserve
			// this order so malformed later notes win over an earlier GNU text-budget failure.
			for note in parse_stream(
				&reader,
				offset,
				size,
				alignment,
				max_entries,
				&mut examined,
				&mut text,
			)? {
				entries.push(to_entry(
					note,
					ElfNoteTableKind::Program,
					index,
					entries.len() as u32,
					reader.little,
					&mut text,
				)?);
			}
		}
	}
	if shnum != 0 {
		if shoff < u64::from(header_size) {
			return Err(format_failure(
				"ELF section header table overlaps the native header.",
			));
		}
		for index in 0..shnum {
			let at = shoff + u64::from(index) * shentsize;
			if reader.u32(at + 4)? != 7 {
				continue;
			}
			let name_offset = reader.u32(at)?;
			let offset = reader.word(at + if wide { 24 } else { 16 })?;
			let size = reader.word(at + if wide { 32 } else { 20 })?;
			reader.slice(offset, size)?;
			if reader.word_bits(at + 8)? & SHF_COMPRESSED != 0 {
				return Err(unsupported("Compressed ELF note sections are unsupported; descriptor file offsets require uncompressed note storage."));
			}
			let declared_alignment = reader.word(at + if wide { 48 } else { 32 })?;
			let alignment = if declared_alignment == 8 { 8 } else { 4 };
			let name = match &names {
				None => None,
				Some(names) => section_name(names, name_offset, &mut text, &mut name_limitations)?,
			};
			tables.push(ElfNoteTable {
				kind: ElfNoteTableKind::Section,
				index,
				name,
				location: ElfNoteRange {
					offset,
					bytes: size,
				},
				alignment,
			});
			for note in parse_stream(
				&reader,
				offset,
				size,
				alignment,
				max_entries,
				&mut examined,
				&mut text,
			)? {
				entries.push(to_entry(
					note,
					ElfNoteTableKind::Section,
					index,
					entries.len() as u32,
					reader.little,
					&mut text,
				)?);
			}
		}
	}
	let mut limitations = if tables.is_empty() {
		vec![
			ABSENT_LIMITATION.to_owned(),
			EXAMINATION_LIMITATION.to_owned(),
		]
	} else {
		vec![
			EXAMINATION_LIMITATION.to_owned(),
			DUPLICATE_LIMITATION.to_owned(),
		]
	};
	limitations.extend(name_limitations);
	Ok(ElfNotesReport {
		artifact,
		format: if wide { "elf64" } else { "elf32" },
		byte_order: if reader.little { "little" } else { "big" },
		machine,
		r#type: object_type,
		type_name: match object_type {
			1 => "relocatable",
			2 => "executable",
			3 => "shared",
			4 => "core",
			_ => "unknown",
		},
		coverage: ElfNotesCoverage {
			status: "complete",
			examined_tables: tables.len() as u32,
			examined_entries: examined,
		},
		tables,
		entries,
		limitations,
	})
}

#[cfg(test)]
#[path = "rea_elf_notes_parser_tests.rs"]
mod tests;
